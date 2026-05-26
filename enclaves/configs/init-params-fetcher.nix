# init params fetcher
# fetch init params from metadata endpoint
{pkgs, ...} @ args: let
  service-name = args.service-name or "init-params-fetcher";
  initParams = "/root/init-params";
  initParamsTmp = "${initParams}.tmp";
  metadataBaseUrl = "http://169.254.169.254";
  tokenUrl = "${metadataBaseUrl}/latest/api/token";
  userDataUrl = "${metadataBaseUrl}/latest/user-data";
  tokenFile = "/run/${service-name}/imds-token";

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
      RuntimeDirectory = service-name;
      RuntimeDirectoryMode = "0700";

      # Fetch an IMDSv2 token first, then use curl's variable expansion to pass
      # it as the metadata header without involving a shell. Download beside the
      # final file, then rename into place only after curl succeeds. The
      # same-directory mv is atomic, so failed or partial downloads cannot be
      # consumed through /root/init-params.
      ExecStartPre = "${pkgs.coreutils}/bin/rm -f ${initParamsTmp} ${tokenFile}";
      ExecStart = [
        "${metadataCurl}/bin/curl --fail --show-error --silent --request PUT --header \"X-aws-ec2-metadata-token-ttl-seconds: 300\" --retry 5 --retry-delay 2 --retry-connrefused --connect-timeout 5 --max-time 20 --output ${tokenFile} ${tokenUrl}"
        "${metadataCurl}/bin/curl --fail --show-error --silent --retry 5 --retry-delay 2 --retry-connrefused --connect-timeout 5 --max-time 60 --variable %imds_token@${tokenFile} --expand-header \"X-aws-ec2-metadata-token: {{imds_token}}\" --output ${initParamsTmp} ${userDataUrl}"
      ];
      ExecStartPost = [
        "${pkgs.coreutils}/bin/mv -f ${initParamsTmp} ${initParams}"
        "${pkgs.coreutils}/bin/rm -f ${tokenFile}"
      ];
      ExecStopPost = "${pkgs.coreutils}/bin/rm -f ${initParamsTmp} ${tokenFile}";
    };
  };
}
