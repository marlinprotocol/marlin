{
  nixpkgs,
  systemConfig,
  crane,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
  crane' = crane.mkLib pkgs;
  commonArgs = {
    strictDeps = true;
    doCheck = false;
    # DOES NOT run the check command
    # short circuits it by running the true command instead
    cargoCheckCommand = "true";

    src = crane'.cleanCargoSource ./.;
    nativeBuildInputs = [
      pkgs.pkg-config
      pkgs.autoPatchelfHook
    ];
    buildInputs = [
      pkgs.tpm2-tss
      pkgs.libgcc
    ];
  };
  deps = crane'.buildDepsOnly commonArgs;
in {
  standard = rec {
    default = crane'.buildPackage (commonArgs
      // {
        cargoArtifacts = deps;
        cargoExtraArgs = "--bin attestation-server";
      });

    service = {...} @ args: let
      service-name = args.service-name or "attestation-server";
      listen-addr = args.listen-addr or "0.0.0.0:1300";
      public-key = args.public-key or "/root/x25519.pub";
      user-data = args.user-data or "/dev/null";
      port = pkgs.lib.toInt (pkgs.lib.last (pkgs.lib.splitString ":" listen-addr));
    in {
      # systemd service
      systemd.services.${service-name} = {
        description = "Run attestation server";
        wantedBy = ["multi-user.target"];
        after = ["local-fs.target" "network.target" "tpm2.target"];
        serviceConfig = {
          Type = "simple";
          ExecStart = ''
            ${default}/bin/attestation-server \
              --listen-addr ${listen-addr} \
              --public-key ${public-key} \
              --user-data ${user-data}
          '';
          Restart = "always";
        };
      };

      # firewall rule
      networking.firewall.allowedTCPPorts = [port];
    };
  };
  custom = rec {
    default = crane'.buildPackage (commonArgs
      // {
        cargoArtifacts = deps;
        cargoExtraArgs = "--bin attestation-server-custom";
      });

    service = {...} @ args: let
      service-name = args.service-name or "attestation-server-custom";
      listen-addr = args.listen-addr or "0.0.0.0:1350";
      port = pkgs.lib.toInt (pkgs.lib.last (pkgs.lib.splitString ":" listen-addr));
    in {
      # systemd service
      systemd.services.${service-name} = {
        description = "Run custom attestation server";
        wantedBy = ["multi-user.target"];
        after = ["local-fs.target" "network.target" "tpm2.target"];
        serviceConfig = {
          Type = "simple";
          ExecStart = ''
            ${default}/bin/attestation-server-custom \
              --listen-addr ${listen-addr}
          '';
          Restart = "always";
        };
      };

      # firewall rule
      networking.firewall.allowedTCPPorts = [port];
    };
  };
}
