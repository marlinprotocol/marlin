{
  nixpkgs,
  systemConfig,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
in rec {
  default = pkgs.stdenv.mkDerivation {
    pname = "limiter-ebpf";
    version = "0.1.0";
    src = ./.;

    nativeBuildInputs = [
      pkgs.llvmPackages.clang-unwrapped
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
      cp limiter.o $out
    '';
  };

  service = {...}: {
    # systemd service to make room for the ebpf program
    systemd.services.limiter-nic-channels = {
      description = "Set ethtool combined channels on default route interface";

      # We must wait for the network to be fully online so 'ip route' works
      wants = ["network-online.target"];
      after = ["network-online.target"];
      wantedBy = ["multi-user.target"];

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;

        ExecStart = pkgs.writeShellScript "set-ethtool-combined" ''
          echo "Setting up ebpf program on ens6"

          # Apply the setting
          ${pkgs.ethtool}/bin/ethtool -L ens6 combined 1
        '';
      };
    };

    # systemd service to make room for the ebpf program
    systemd.services.limiter-ebpf = {
      description = "Load ebpf program";

      wants = ["limiter-nic-channels.service"];
      after = ["limiter-nic-channels.service"];
      wantedBy = ["multi-user.target"];

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = pkgs.writeShellScript "load-ebpf" ''
          ${pkgs.iproute2}/bin/ip link set dev ens6 xdp obj ${default} sec xdp
        '';
      };
    };
  };
}
