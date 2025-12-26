{
  nixConfig = {
    extra-substituters = ["https://oyster.cachix.org"];
    extra-trusted-public-keys = ["oyster.cachix.org-1:QEXLEQvMA7jPLn4VZWVk9vbtypkXhwZknX+kFgDpYQY="];
  };
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/release-25.11";
    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs = {
    self,
    nixpkgs,
    naersk,
  }: let
    systemBuilder = systemConfig: rec {
      external.nitrotpm-tools = import ./external/nitrotpm-tools.nix {
        inherit nixpkgs systemConfig naersk;
      };
      attestation.server = import ./attestation/server {
        inherit nixpkgs systemConfig naersk;
      };
      enclaves.testing.green = import ./enclaves/testing/green.nix {
        inherit nixpkgs systemConfig;
        keygen-x25519 = initialization.keygen.x25519.service;
        attestation-server = attestation.server.service;
        nitrotpm-tools = external.nitrotpm-tools.default;
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
        creator = kms.creator.service;
      };
    };
  in {
    formatter = {
      "x86_64-linux" = nixpkgs.legacyPackages."x86_64-linux".alejandra;
      "aarch64-linux" = nixpkgs.legacyPackages."aarch64-linux".alejandra;
    };
    packages = {
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
  };
}
