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
in rec {
  default = crane'.buildPackage (commonArgs
    // {
      cargoArtifacts = deps;
    });

  service = {...} @ args: let
    service-name = args.service-name or "attestation-server-custom";
    ip-addr = args.ip-addr or "127.0.0.1:1350";
    port = pkgs.lib.toInt (pkgs.lib.last (pkgs.lib.splitString ":" ip-addr));
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
            --ip-addr ${ip-addr}
        '';
        Restart = "always";
      };
    };

    # firewall rule
    networking.firewall.allowedTCPPorts = [port];
  };
}
