# Image for testing green images
{
  nixpkgs,
  systemConfig,
  nitrotpm-tools,
  keygen-x25519,
  attestation-server,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
  nixosConfig = {...}: {
    imports = [
      # build as a green image
      (./. + "/../configs/green.nix")
    ];

    # systemd service for testing
    systemd.services.hello = {
      description = "Hello";
      wantedBy = ["multi-user.target"];
      serviceConfig = {
        Type = "simple";
        ExecStart = pkgs.writeScript "loop.sh" ''
          #!${pkgs.bash}/bin/bash

          while true; do
            echo "Hello from stdout!"
            echo "Hello from console!" > /dev/console
            echo "Hello from kmsg!" > /dev/kmsg
            sleep 1
          done
        '';
        StandardOutput = "journal+console";
        StandardError = "journal+console";
      };
    };

    # root ssh for testing
    services.openssh = {
      enable = true;
      settings = {
        PermitRootLogin = "yes";
        PasswordAuthentication = true;
      };
    };
    users.users.root.initialPassword = "greenroot";

    # disable firewall while testing
    networking.firewall.enable = false;
  };
  nixosSystem = nixpkgs.lib.nixosSystem {
    system = systemConfig.system;
    modules = [nixosConfig];
    specialArgs = {
      lib = pkgs.lib;
      modulesPath = "${nixpkgs}/nixos/modules";
      systemConfig = systemConfig;
      inherit keygen-x25519 attestation-server;
    };
  };
  measurement = pkgs.runCommand "measurement" {} ''
    mkdir $out
    ${nitrotpm-tools}/bin/nitro-tpm-pcr-compute -i ${nixosSystem.config.system.build.uki}/${nixosSystem.config.system.boot.loader.ukiFile} > $out/measurement.json
  '';
in {
  default = pkgs.symlinkJoin {
    name = "measured-image";
    paths = [
      nixosSystem.config.system.build.finalImage
      measurement
    ];
  };
}
