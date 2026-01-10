{
  nixConfig = {
    extra-substituters = ["https://oyster.cachix.org"];
    extra-trusted-public-keys = ["oyster.cachix.org-1:QEXLEQvMA7jPLn4VZWVk9vbtypkXhwZknX+kFgDpYQY="];
  };
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/release-25.11";
    crane = {
      url = "github:ipetkov/crane";
    };
    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs = {
    self,
    nixpkgs,
    crane,
    naersk,
  }: let
    systemBuilder = systemConfig: rec {
      attestation.server = import ./attestation/server {
        inherit nixpkgs systemConfig crane;
      };
      attestation.server-custom = import ./attestation/server-custom {
        inherit nixpkgs systemConfig crane;
      };
      enclaves.gauge = import ./enclaves/gauge {
        inherit nixpkgs systemConfig crane;
      };
      enclaves.testing.custom-attestations = import ./enclaves/testing/custom-attestations.nix {
        inherit nixpkgs systemConfig;
        nitrotpm-tools = external.nitrotpm-tools.default;
        gauge = enclaves.gauge.default;
        attestation-server-custom = attestation.server-custom.service;
      };
      enclaves.testing.green = import ./enclaves/testing/green.nix {
        inherit nixpkgs systemConfig;
        nitrotpm-tools = external.nitrotpm-tools.default;
        gauge = enclaves.gauge.default;
        keygen-x25519 = initialization.keygen.x25519.service;
        attestation-server = attestation.server.service;
      };
      external.nitrotpm-tools = import ./external/nitrotpm-tools.nix {
        inherit nixpkgs systemConfig naersk;
      };
      initialization.keygen = import ./initialization/keygen {
        inherit nixpkgs systemConfig naersk;
      };
      kms.creator = import ./kms/creator {
        inherit nixpkgs systemConfig naersk;
      };
      kms.creator-enclave = import ./kms/creator-enclave {
        inherit nixpkgs systemConfig;
        nitrotpm-tools = external.nitrotpm-tools.default;
        keygen-secp256k1 = initialization.keygen.secp256k1.service;
        attestation-server = attestation.server.service;
        kms-creator = kms.creator.service;
      };
      kms.derive-server = import ./kms/derive-server {
        inherit nixpkgs systemConfig naersk;
      };
      kms.root-server = import ./kms/root-server {
        inherit nixpkgs systemConfig naersk;
      };
      kms.root-server-enclave = import ./kms/root-server-enclave {
        inherit nixpkgs systemConfig;
        nitrotpm-tools = external.nitrotpm-tools.default;
        keygen-secp256k1 = initialization.keygen.secp256k1.service;
        attestation-server = attestation.server.service;
        kms-root-server = kms.root-server.service;
      };
    };
    check = {
      system,
      packages,
    }: let
      pkgs = nixpkgs.legacyPackages.${system};

      # recursive function to find all derivations
      findDrvs = attrs:
        if pkgs.lib.isDerivation attrs
        then [attrs]
        else if builtins.isAttrs attrs
        then pkgs.lib.concatLists (pkgs.lib.mapAttrsToList (k: v: findDrvs v) attrs)
        else [];

      # get all derivations
      allDrvs = findDrvs packages.${system};

      # get paths but discard the dependency context
      # does only evaluation and prevents full build
      drvPaths = map (drv: builtins.unsafeDiscardStringContext drv.drvPath) allDrvs;
    in
      pkgs.runCommand "eval-all" {
        paths = builtins.concatStringsSep "\n" drvPaths;
      } ''
        echo "Checked evaluation for:"
        echo "$paths"
        touch $out
      '';
  in rec {
    formatter = {
      "x86_64-linux" = nixpkgs.legacyPackages."x86_64-linux".alejandra;
      "aarch64-linux" = nixpkgs.legacyPackages."aarch64-linux".alejandra;
    };
    legacyPackages = {
      "x86_64-linux" = systemBuilder {
        system = "x86_64-linux";
        efi_arch = "x64";
        repart_arch = "x86-64";
      };
      "aarch64-linux" = systemBuilder {
        system = "aarch64-linux";
        efi_arch = "aa64";
        repart_arch = "arm64";
      };
    };
    # check if all derivations are valid
    # does NOT check if everything builds properly, too expensive
    # just preliminiary evaluation stage checks
    checks = {
      "x86_64-linux".eval-all = check {
        system = "x86_64-linux";
        packages = legacyPackages;
      };
      "aarch64-linux".eval-all = check {
        system = "aarch64-linux";
        packages = legacyPackages;
      };
    };
  };
}
