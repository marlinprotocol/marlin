{
  nixpkgs,
  systemConfig,
  naersk,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
  naersk' = pkgs.callPackage naersk {};
in rec {
  default = naersk'.buildPackage {
    src = ./.;
    nativeBuildInputs = [
      pkgs.pkg-config
      pkgs.autoPatchelfHook
    ];
    buildInputs = [
      pkgs.tpm2-tss
      pkgs.libgcc
    ];
  };

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
          ${default}/bin/attestation-server \
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
