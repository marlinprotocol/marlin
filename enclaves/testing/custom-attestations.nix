# Image with exposed custom attestation server
{
  nixpkgs,
  systemConfig,
  nitrotpm-tools,
  attestation-server-custom,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
  nixosConfig = {...}: {
    imports = [
      # base config
      (./. + "/../../enclaves/configs/base.nix")
      # disk config
      (./. + "/../../enclaves/configs/disk-ro.nix")
      # custom attestation server
      (attestation-server-custom {
        ip-addr = "0.0.0.0:1300";
      })
    ];

    # image id and version
    system.image.id = "marlin-custom-attestations";
    system.image.version = "v0.1.0";

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
