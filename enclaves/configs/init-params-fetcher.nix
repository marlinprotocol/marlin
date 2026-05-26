# init params fetcher
# Fetch enclave init params from EC2 user-data through IMDSv2, without adding
# bash or exposing partially downloaded params to later services.
{pkgs, ...} @ args: let
  service-name = args.service-name or "init-params-fetcher";

  # Final params path consumed by enclave services. Downloads first land beside
  # it so the final rename stays atomic on the root filesystem.
  initParams = "/root/init-params";
  initParamsTmp = "${initParams}.tmp";

  # EC2 metadata endpoints. This module intentionally uses IMDSv2 only; there
  # is no IMDSv1 fallback because users should be able to set HttpTokens=required.
  metadataBaseUrl = "http://169.254.169.254";
  tokenUrl = "${metadataBaseUrl}/latest/api/token";
  userDataUrl = "${metadataBaseUrl}/latest/user-data";

  # The IMDSv2 token is short-lived and only needed while this oneshot runs.
  # Store it under RuntimeDirectory rather than beside the final init params.
  tokenFile = "/run/${service-name}/imds-token";

  # curl's bin output includes shell completions that reference bash. Copy just
  # the executable so the runtime closure contains libcurl and its libraries,
  # but not the completion files.
  curl = pkgs.runCommand "curl" {} ''
    mkdir -p "$out/bin"
    cp ${pkgs.curlMinimal.bin}/bin/curl "$out/bin/curl"
  '';
in {
  # Metadata access needs the stage-2 network stack and matching kernel support.
  marlin.kernel.fragments = ["network"];
  marlin.systemd.packageOptions = {
    withNetworkd = true;
  };
  networking.useNetworkd = true;
  networking.useDHCP = true;
  systemd.network.enable = true;

  # Fetch init params before normal multi-user services consume them.
  systemd.services.${service-name} = {
    description = "Retrieve init params";
    wantedBy = ["multi-user.target"];
    wants = ["network-online.target"];
    after = ["local-fs.target" "network-online.target"];

    # Fetch an IMDSv2 token first, then use curl's variable expansion to pass
    # it as the metadata header without involving a shell. Download beside the
    # final file, then rename into place only after curl succeeds. The
    # same-directory mv is atomic, so failed or partial downloads cannot be
    # consumed through /root/init-params.
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;

      # Private scratch directory for the IMDSv2 token. systemd creates it
      # before ExecStartPre and removes it when the service is stopped.
      RuntimeDirectory = service-name;
      RuntimeDirectoryMode = "0700";

      # Clean up failed or interrupted attempts.
      ExecStartPre = "${pkgs.coreutils}/bin/rm -f ${initParamsTmp} ${tokenFile}";

      # systemd runs list entries in order. The first request creates the IMDSv2
      # token; the second reads it from disk and expands it into the metadata
      # header while downloading user-data to the temporary params file.
      ExecStart = [
        "${curl}/bin/curl --fail --show-error --silent --request PUT --header \"X-aws-ec2-metadata-token-ttl-seconds: 300\" --retry 5 --retry-delay 2 --retry-connrefused --connect-timeout 5 --max-time 20 --output ${tokenFile} ${tokenUrl}"
        "${curl}/bin/curl --fail --show-error --silent --retry 5 --retry-delay 2 --retry-connrefused --connect-timeout 5 --max-time 60 --variable %imds_token@${tokenFile} --expand-header \"X-aws-ec2-metadata-token: {{imds_token}}\" --output ${initParamsTmp} ${userDataUrl}"
      ];

      # Publish the completed params file only after both IMDSv2 requests
      # succeed, then remove the token while keeping the service active.
      ExecStartPost = [
        "${pkgs.coreutils}/bin/mv -f ${initParamsTmp} ${initParams}"
        "${pkgs.coreutils}/bin/rm -f ${tokenFile}"
      ];

      # Clean up failed or interrupted attempts. This also handles manual stops
      # after RemainAfterExit keeps the successful oneshot active.
      ExecStopPost = "${pkgs.coreutils}/bin/rm -f ${initParamsTmp} ${tokenFile}";
    };
  };
}
