{
  nixpkgs,
  systemConfig,
  fenix,
  naersk,
}:
if systemConfig.static
then
  throw ''

    ---------------------------------------------------------------
    ERROR: Non-static build detected.

    This project cannot produce a static build.

    Current system: ${systemConfig.system}
    Current target: ${systemConfig.rust_target}
    ---------------------------------------------------------------
  ''
else let
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
      pkgs.autoPatchelfHook
    ];
    buildInputs = [
      pkgs.tpm2-tss
      pkgs.libgcc
    ];
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
    service-name = args.service-name or "attestation-server";
    ip-addr = args.ip-addr or "0.0.0.0:1300";
    pub-key = args.pub-key or "/root/x25519.pub";
    user-data = args.user-data or "/dev/null";
    port = pkgs.lib.toInt (pkgs.lib.last (pkgs.lib.splitString ":" ip-addr));
  in {
    # systemd service
    systemd.services.${service-name} = {
      description = "Run attestation server";
      wantedBy = ["multi-user.target"];
      after = ["local-fs.target" "network.target" "tpm2.target"];
      serviceConfig = {
        Type = "simple";
        ExecStart = ''
          ${uncompressed}/bin/attestation-server \
            --ip-addr ${ip-addr} \
            --pub-key ${pub-key} \
            --user-data ${user-data}
        '';
        Restart = "always";
      };
    };

    # firewall rule
    networking.firewall.allowedTCPPorts = [port];
  };
}
