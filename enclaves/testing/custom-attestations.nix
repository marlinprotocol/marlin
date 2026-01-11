# Image with exposed custom attestation server
{
  nixpkgs,
  systemConfig,
  nitrotpm-tools,
  gauge,
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
        listen-addr = "0.0.0.0:1300";
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
  measurement =
    pkgs.runCommand "measurement" {
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
in {
  default = pkgs.symlinkJoin {
    name = "measured-image";
    paths = [
      nixosSystem.config.system.build.finalImage
      measurement
    ];
  };
}
