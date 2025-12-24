{
  nixpkgs,
  systemConfig,
  fenix,
  naersk,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
  target = systemConfig.rust_target;
  toolchain = with fenix.packages.${system};
    combine [
      stable.cargo
      stable.rustc
      targets.${target}.stable.rust-std
    ];
  naersk' = naersk.lib.${system}.override {
    cargo = toolchain;
    rustc = toolchain;
  };
  cc =
    if systemConfig.static
    then pkgs.pkgsStatic.stdenv.cc
    else pkgs.stdenv.cc;
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
  uncompressed = naersk'.buildPackage {
    src = ./.;
    CARGO_BUILD_TARGET = target;
    TARGET_CC = "${cc}/bin/${cc.targetPrefix}cc";
    nativeBuildInputs = [cc];
  };

  compressed =
    pkgs.runCommand "compressed" {
      nativeBuildInputs = [pkgs.upx];
    } ''
      mkdir -p $out/bin
      cp ${uncompressed}/bin/* $out/bin/
      chmod +w $out/bin/*
      upx $out/bin/*
    '';

  default = compressed;

  x25519.service = service {
    binaries = uncompressed;
    key-type = "x25519";
  };
  secp256k1.service = service {
    binaries = uncompressed;
    key-type = "secp256k1";
  };
  ed25519.service = service {
    binaries = uncompressed;
    key-type = "ed25519";
  };
}
