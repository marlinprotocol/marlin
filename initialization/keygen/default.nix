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
  service = {
    binaries,
    key-type,
  }: {...} @ args: let
    service-name = args.service-name or "keygen-${key-type}";
    key-dir = args.key-dir or "/root";
    key-name = args.key-name or key-type;
  in {
    # systemd service
    systemd.services.${service-name} = {
      description = "Generate ${key-type} keypair";
      wantedBy = ["multi-user.target"];
      after = ["local-fs.target"];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${binaries}/bin/keygen-${key-type} --secret ${key-dir}/${key-name}.sec --public ${key-dir}/${key-name}.pub";
      };
    };
  };
in rec {
  default = crane'.buildPackage (commonArgs
    // {
      cargoArtifacts = deps;
    });
  x25519.service = service {
    binaries = default;
    key-type = "x25519";
  };
  secp256k1.service = service {
    binaries = default;
    key-type = "secp256k1";
  };
  ed25519.service = service {
    binaries = default;
    key-type = "ed25519";
  };
}
