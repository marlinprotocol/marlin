# init params fetcher
# fetch init params from metadata endpoint
{pkgs, ...} @ args: let
  service-name = args.service-name or "init-params-fetcher";
in {
  # systemd service
  systemd.services.${service-name} = {
    description = "Retrieve init params";
    wantedBy = ["multi-user.target"];
    after = ["local-fs.target" "network-online.target"];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      set -euo pipefail

      tmp=$(${pkgs.coreutils}/bin/mktemp /root/init-params.XXXXXX)
      trap '${pkgs.coreutils}/bin/rm -f "$tmp"' EXIT

      ${pkgs.curl}/bin/curl \
        --fail \
        --show-error \
        --silent \
        --location \
        --retry 5 \
        --retry-delay 2 \
        --retry-connrefused \
        --connect-timeout 5 \
        --max-time 60 \
        --output "$tmp" \
        http://169.254.169.254/latest/user-data

      ${pkgs.coreutils}/bin/mv "$tmp" /root/init-params
      trap - EXIT
    '';
  };
}
