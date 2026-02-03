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

        # The script logic:
        # 1. Get the line describing the route to 1.1.1.1
        # 2. Extract the word after "dev"
        # 3. Run ethtool on that interface
        ExecStart = pkgs.writeShellScript "set-ethtool-combined" ''
          # Find the interface name (e.g., ens5, eth0)
          IFACE=$(${pkgs.iproute2}/bin/ip -o route get 1.1.1.1 | ${pkgs.gnused}/bin/sed -n 's/.*dev \([^ ]*\).*/\1/p')

          if [ -z "$IFACE" ]; then
            echo "Could not determine default interface. Skipping ethtool optimization."
            exit 0
          fi

          echo "Detected primary interface: $IFACE"

          # Apply the setting
          ${pkgs.ethtool}/bin/ethtool -L "$IFACE" combined 1
        '';
      };
    };

    # systemd service to make room for the ebpf program
    systemd.services.limiter-ebpf = {
      description = "Set ethtool combined channels on default route interface";

      wants = ["limiter-nic-channels.service"];
      after = ["limiter-nic-channels.service"];
      wantedBy = ["multi-user.target"];

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = pkgs.writeShellScript "load-ebpf" ''
          ${pkgs.iproute2}/bin/ip link set dev $(${pkgs.iproute2}/bin/ip route get 1.1.1.1 | grep -oP '(?<=dev )[^ ]+') xdp obj ${default} sec xdp
        '';
      };
    };
  };
}
