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
in rec {
  default = crane'.buildPackage (commonArgs
    // {
      cargoArtifacts = deps;
    });

  service = {...}: {
    # systemd service to make room for the ebpf program
    systemd.services.nic-channels = {
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

    # systemd service
    systemd.services.limiter-server = {
      description = "Run limiter server";
      wantedBy = ["multi-user.target"];
      wants = ["nic-channels.target"];
      after = ["nic-channels.target"];
      serviceConfig = {
        Type = "simple";
        ExecStart = ''
          ${default}/bin/limiter-server
        '';
        Restart = "always";
      };
    };

    # firewall rule
    networking.firewall.allowedTCPPorts = [3000];
  };
}
