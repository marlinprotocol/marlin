# Image for testing green images
{
  nixpkgs,
  systemConfig,
  kernels,
  nitrotpm-tools,
  gauge,
  keygen-x25519,
  attestation-server,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
  mkImage = target: let
    nixosConfig = {
      config,
      lib,
      ...
    }: {
      imports = [
        # build as a green image
        (./. + "/../configs/green.nix")
      ];

      marlin.kernel.target = target;

      boot.kernelPackages = pkgs.linuxPackagesFor (kernels.mkKernel {
        inherit target;
        fragments = config.marlin.kernel.fragments;
      });

      /*
      # systemd service for testing
      systemd.services.hello = {
        description = "Hello";
        wantedBy = ["multi-user.target"];
        serviceConfig = {
          Type = "simple";
          ExecStart = pkgs.writeScript "loop.sh" ''
            #!${pkgs.dash}/bin/dash

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
      */

      /*
      # root ssh for testing
      services.openssh = {
        enable = true;
        settings = {
          PermitRootLogin = "yes";
          PasswordAuthentication = true;
        };
      };
      users.users.root.initialPassword = "greenroot";
      */

      # disable firewall while testing
      networking.firewall.enable = false;

      # tpm2-tools pulls in bash wrapper scripts; keep it out while this image is
      # built with the bashless profile.
      # environment.systemPackages = [pkgs.tpm2-tools];
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
    measurement =
      pkgs.runCommand "measurement-${target}" {
        nativeBuildInputs = [pkgs.jq];
      } ''
        mkdir $out
        ${nitrotpm-tools}/bin/nitro-tpm-pcr-compute -i ${nixosSystem.config.system.build.uki}/${nixosSystem.config.system.boot.loader.ukiFile} > nitro-measurement.json
        ${gauge}/bin/gauge ${nixosSystem.config.system.build.finalImage}/*.raw ${nixosSystem.config.system.build.uki}/${nixosSystem.config.system.boot.loader.ukiFile} gauge-measurement.json
        jq -s '
          # 1. The Deep Merge
          reduce .[] as $item ({}; . * $item)

          # 2. The Custom Sort
          | .Measurements |= (
              to_entries
              | sort_by( .key | sub("(?<n>\\d+)"; .n | "00000" + . | .[-5:]) )
              | from_entries
            )
        ' nitro-measurement.json gauge-measurement.json > $out/measurement.json
      '';
  in
    pkgs.symlinkJoin {
      name = "measured-${target}-image";
      paths = [
        nixosSystem.config.system.build.finalImage
        measurement
      ];
    };
  qemu = mkImage "qemu";
  ec2 = mkImage "ec2";
in {
  inherit qemu ec2;
  default = ec2;
}
