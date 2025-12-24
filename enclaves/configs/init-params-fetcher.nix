# init params fetcher
# fetch init params from metadata endpoint
{pkgs, ...} @ args: let
  service-name = args.service-name or "init-params-fetcher";
in {
  # systemd service
  systemd.services.${service-name} = {
    description = "Retrieve init params";
    wantedBy = ["multi-user.target"];
    after = ["local-fs.target" "network.target"];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = ''
        ${pkgs.curl}/bin/curl http://169.254.169.254/latest/user-data -o /root/init-params
      '';
    };
  };
}
