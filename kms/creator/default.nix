{
  nixpkgs,
  systemConfig,
  naersk,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
  naersk' = pkgs.callPackage naersk {};
  projectSrc = ./.;
  libSrc = ../derive-utils;
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
in rec {
  default = naersk'.buildPackage {
    src = combinedSrc;
  };

  service = {dkg-public-key, ...} @ args: let
    service-name = args.service-name or "kms-creator";
    listen-addr = args.listen-addr or "0.0.0.0:1100";
    signer = args.signer or "/root/secp256k1.sec";
    condition-path = args.condition-path or "/root/init-params";
    port = pkgs.lib.toInt (pkgs.lib.last (pkgs.lib.splitString ":" listen-addr));
  in {
    # systemd service
    systemd.services.${service-name} = {
      description = "Run KMS creator";
      wantedBy = ["multi-user.target"];
      after = ["local-fs.target" "network.target"];
      serviceConfig = {
        Type = "simple";
        ExecStart = ''
          ${default}/bin/kms-creator \
            --listen-addr ${listen-addr} \
            --signer ${signer} \
            --dkg-public-key ${dkg-public-key} \
            --condition-path ${condition-path}
        '';
        Restart = "always";
      };
    };

    # firewall rule
    networking.firewall.allowedTCPPorts = [port];
  };
}
