# Image for kms-creator enclave
{
  nixpkgs,
  systemConfig,
  nitrotpm-tools,
  gauge,
  keygen-secp256k1,
  attestation-server,
  kms-creator,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";

  nixosConfig = {...}: {
    imports = [
      # base config
      (./. + "/../../enclaves/configs/base.nix")
      # disk config
      (./. + "/../../enclaves/configs/disk-ro.nix")
      # dns config
      (./. + "/../../enclaves/configs/dns.nix")

      # enclave services
      (./. + "/../../enclaves/configs/init-params-fetcher.nix")
      keygen-secp256k1
      (attestation-server {
        public-key = "/root/secp256k1.pub";
        user-data = "/root/init-params";
      })
      (kms-creator {
        dkg-public-key = "868c3d012a5d524f0939e4ee4d60b738b4c44448ec286a5361e15ffbf2641e2df25363a204a738231e5f1a9621999741";
      })
    ];

    # image id and version
    system.image.id = "marlin-kms-creator";
    system.image.version = "v0.1.0";

    # service ordering
    systemd.services.attestation-server.after = ["keygen-secp256k1.service" "init-params-fetcher.service"];
    systemd.services.kms-creator.after = ["keygen-secp256k1.service" "init-params-fetcher.service"];
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
