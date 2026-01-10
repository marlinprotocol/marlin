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
    ritual,
    threshold,
    ...
  } @ args: let
    service-name = args.service-name or "kms-root-server";
    seed-path = args.seed-path or "/root/init-params";
    scallop-listen-addr = args.scallop-listen-addr or "0.0.0.0:1100";
    public-listen-addr = args.public-listen-addr or "0.0.0.0:1101";
    signer = args.signer or "/root/secp256k1.sec";
    porter = args.porter or "https://porter.nucypher.io/decrypt";
    coordinator = args.coordinator or "0xE74259e3dafe30bAA8700238e324b47aC98FE755";
    rpc = args.rpc or "https://polygon-rpc.com";
    delay = args.delay or "1800";
    scallop-port = pkgs.lib.toInt (pkgs.lib.last (pkgs.lib.splitString ":" scallop-listen-addr));
    public-port = pkgs.lib.toInt (pkgs.lib.last (pkgs.lib.splitString ":" public-listen-addr));
  in {
    # systemd service
    systemd.services.${service-name} = {
      description = "Run KMS root server";
      wantedBy = ["multi-user.target"];
      after = ["local-fs.target" "network.target"];
      serviceConfig = {
        Type = "simple";
        ExecStart = ''
          ${default}/bin/kms-root-server \
            --seed-path ${seed-path} \
            --scallop-listen-addr ${scallop-listen-addr} \
            --public-listen-addr ${public-listen-addr} \
            --signer ${signer} \
            --porter ${porter} \
            --coordinator ${coordinator} \
            --rpc ${rpc} \
            --threshold ${threshold} \
            --delay ${delay}
        '';
        Restart = "always";
      };
    };

    # firewall rule
    networking.firewall.allowedTCPPorts = [scallop-port public-port];
  };
}
