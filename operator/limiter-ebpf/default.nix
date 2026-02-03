{
  nixpkgs,
  systemConfig,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
in
  pkgs.stdenv.mkDerivation {
    pname = "limiter-ebpf";
    version = "0.1.0";
    src = ./.;

    nativeBuildInputs = [
      pkgs.clang
      pkgs.llvm
    ];

    buildInputs = [
      pkgs.libbpf
      pkgs.linuxHeaders
    ];

    # Explicitly include paths for headers
    # - libbpf for <bpf/bpf_*.h>
    # - linuxHeaders for <linux/*.h>
    buildPhase = ''
      clang -O2 -g -target bpf \
        -I${pkgs.libbpf}/include \
        -I${pkgs.linuxHeaders}/include \
        -c limiter.c -o limiter.o
    '';

    installPhase = ''
      mkdir -p $out/lib/bpf
      cp limiter.o $out/lib/bpf/
    '';
  }
