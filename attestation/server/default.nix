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
in rec {
  uncompressed = naersk'.buildPackage {
    src = ./.;
    CARGO_BUILD_TARGET = target;
    TARGET_CC = "${cc}/bin/${cc.targetPrefix}cc";
    nativeBuildInputs = [
      cc
      pkgs.pkg-config
    ];
    buildInputs = [
      pkgs.pkgsStatic.tpm2-tss
      pkgs.pkgsStatic.openssl
    ];

    PKG_CONFIG_ALL_STATIC = 1;

    postConfigure = ''
      ar rcs libdl.a
      export LIBRARY_PATH="$PWD:$LIBRARY_PATH"
    '';
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
}
