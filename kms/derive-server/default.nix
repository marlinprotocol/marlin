{
  nixpkgs,
  systemConfig,
  crane,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
  crane' = crane.mkLib pkgs;
  projectSrc = crane'.cleanCargoSource ./.;
  libSrc = crane'.cleanCargoSource ../derive-utils;
  combinedSrc = pkgs.runCommand "combined-src" {} ''
    # Copy the project
    cp -r ${projectSrc} $out
    chmod -R +w $out

    # Copy the library into the project directory
    mkdir -p $out/libs/derive-utils
    cp -r ${libSrc}/* $out/libs/derive-utils

    # Patch Cargo.toml to point to the new library location
    substituteInPlace $out/Cargo.toml \
      --replace 'path = "../derive-utils"' 'path = "./libs/derive-utils"'
  '';
  commonArgs = {
    strictDeps = true;
    doCheck = false;
    # DOES NOT run the check command
    # short circuits it by running the true command instead
    cargoCheckCommand = "true";

    src = combinedSrc;
  };
  deps = crane'.buildDepsOnly commonArgs;
in rec {
  default = crane'.buildPackage (commonArgs
    // {
      cargoArtifacts = deps;
    });

  service = {
    kms-endpoint,
    kms-pubkey,
    root-server-config,
    contract-address-file,
    ...
  } @ args: let
    service-name = args.service-name or "kms-derive-server";
    listen-addr = args.listen-addr or "127.0.0.1:1100";
    attestation-endpoint = args.attestation-endpoint or "http://127.0.0.1:1300/attestation/raw";
    secret-path = args.secret-path or "/root/x25519.sec";
  in {
    # systemd service
    systemd.services.${service-name} = {
      description = "Run KMS derive server";
      wantedBy = ["multi-user.target"];
      after = ["local-fs.target" "network.target"];
      serviceConfig = {
        Type = "simple";
        ExecStart = ''
          ${default}/bin/kms-derive-server \
            --listen-addr ${listen-addr} \
            --attestation-endpoint ${attestation-endpoint} \
            --secret-path ${secret-path} \
            ${
            if contract-address-file != null
            then "--contract-address-file ${contract-address-file}"
            else ""
          } \
            ${
            if root-server-config != null
            then "--root-server-config ${root-server-config}"
            else "--kms-endpoint ${kms-endpoint} --kms-pubkey ${kms-pubkey}"
          }
        '';
        Restart = "always";
      };
    };
  };
}
