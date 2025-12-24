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
  projectSrc = ./.;
  libSrc = ../derive-utils;
  combinedSrc = pkgs.runCommand "combined-src" {} ''
    # Copy the project
    cp -r ${projectSrc} $out
    chmod -R +w $out

    # Copy the library into the project directory
    mkdir -p $out/libs/derive-utils
    cp -r ${libSrc}/* $out/libs/derive-utils

    # Patch Cargo.toml to point to the new library location
    substituteInPlace $out/Cargo.toml \
      --replace 'path = "../derive-utils"' 'path = "./libs/derive-utils"'
  '';
in rec {
  uncompressed = naersk'.buildPackage {
    src = combinedSrc;
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

  service = {...} @ args: let
    service-name = args.service-name or "kms-creator";
    listen-addr = args.listen-addr or "0.0.0.0:1100";
    signer = args.signer or "/root/secp256k1.sec";
    condition-path = args.condition-path or /root/init-params;
    dkg-public-key = args.dkg-public-key or "868c3d012a5d524f0939e4ee4d60b738b4c44448ec286a5361e15ffbf2641e2df25363a204a738231e5f1a9621999741";
  in {
    # systemd service
    systemd.services.${service-name} = {
      description = "Run KMS creator";
      wantedBy = ["multi-user.target"];
      after = ["local-fs.target"];
      serviceConfig = {
        Type = "simple";
        ExecStart = ''
          ${uncompressed}/bin/kms-creator \
            --listen-addr ${listen-addr} \
            --signer ${signer} \
            --dkg-public-key ${dkg-public-key} \
            --condition-path ${condition-path}
        '';
        Restart = "always";
      };
    };
  };
}
