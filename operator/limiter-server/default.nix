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
  };
  deps = crane'.buildDepsOnly commonArgs;
in rec {
  default = crane'.buildPackage (commonArgs
    // {
      cargoArtifacts = deps;
    });

  service = {...}: {
    # systemd service
    systemd.services.limiter-server = {
      description = "Run limiter server";
      wantedBy = ["multi-user.target"];
      after = ["local-fs.target" "network.target"];
      serviceConfig = {
        Type = "simple";
        ExecStart = ''
          ${default}/bin/limiter-server
        '';
        Restart = "always";
      };
    };

    # firewall rule
    networking.firewall.allowedTCPPorts = [3000];
  };
}
