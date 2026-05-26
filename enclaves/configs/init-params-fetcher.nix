# init params fetcher
# fetch init params from metadata endpoint
{pkgs, ...} @ args: let
  service-name = args.service-name or "init-params-fetcher";
  initParams = "/root/init-params";
  initParamsTmp = "${initParams}.tmp";
  userDataUrl = "http://169.254.169.254/latest/user-data";

  # curl's bin output includes shell completions that reference bash. Copy just
  # the executable so the runtime closure contains libcurl and its libraries,
  # but not the completion files.
  metadataCurl = pkgs.runCommand "metadata-curl" {} ''
    mkdir -p "$out/bin"
    cp ${pkgs.curlMinimal.bin}/bin/curl "$out/bin/curl"
  '';
in {
  marlin.kernel.fragments = ["network"];
  marlin.systemd.packageOptions = {
    withNetworkd = true;
  };

  # Opt back into runtime networkd for metadata access. DNS is not needed for
  # the link-local metadata endpoint used below.
  networking.useNetworkd = true;
  networking.useDHCP = true;
  systemd.network.enable = true;

  # systemd service
  systemd.services.${service-name} = {
    description = "Retrieve init params";
    wantedBy = ["multi-user.target"];
    wants = ["network-online.target"];
    after = ["local-fs.target" "network-online.target"];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;

      # Download beside the final file, then rename into place only after curl
      # succeeds. The same-directory mv is atomic, so failed or partial
      # downloads cannot be consumed through /root/init-params.
      ExecStartPre = "${pkgs.coreutils}/bin/rm -f ${initParamsTmp}";
      ExecStart = "${metadataCurl}/bin/curl --fail --show-error --silent --location --retry 5 --retry-delay 2 --retry-connrefused --connect-timeout 5 --max-time 60 --output ${initParamsTmp} ${userDataUrl}";
      ExecStartPost = "${pkgs.coreutils}/bin/mv -f ${initParamsTmp} ${initParams}";
      ExecStopPost = "${pkgs.coreutils}/bin/rm -f ${initParamsTmp}";
    };
  };
}
