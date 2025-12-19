# attestation server config
# set up attestation server as a service
{attestation-server, ...} @ args: let
  service-name = args.service-name or "attestation-server";
  ip-addr = args.ip-addr or "0.0.0.0:1300";
  pub-key = args.pub-key or "/root/x25519.pub";
  user-data = args.user-data or "/dev/null";
in {
  # systemd service
  systemd.services.${service-name} = {
    description = "Run attestation server";
    wantedBy = ["multi-user.target"];
    after = ["local-fs.target"];
    serviceConfig = {
      Type = "simple";
      ExecStart = "${attestation-server}/bin/attestation-server --ip-addr ${ip-addr} --pub-key ${pub-key} --user-data ${user-data}";
    };
  };
}
