# init params fetcher
# fetch init params from metadata endpoint
{...} @ args: let
  service-name = args.service-name or "init-params-fetcher";
in {
  # systemd service
  systemd.services.${service-name} = {
    description = "Retrieve init params";
    wantedBy = ["multi-user.target"];
    after = ["local-fs.target"];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = ''
        curl http://169.254.169.254/latest/user-data > /root/init-params
      '';
    };
  };
}
