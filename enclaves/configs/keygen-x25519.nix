# keygen-x25519 config
# one shot service to generate x25519 keys
{keygen-x25519, ...} @ args: let
  service-name = args.service-name or "keygen-x25519";
  key-dir = args.key-dir or "/root";
  key-name = args.key-name or "x25519";
in {
  # systemd service
  systemd.services.${service-name} = {
    description = "Generate x25519 keypair";
    wantedBy = ["multi-user.target"];
    after = ["local-fs.target"];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = "${keygen-x25519}/bin/keygen-x25519 --secret ${key-dir}/${key-name}.sec --public ${key-dir}/${key-name}.pub";
    };
  };
}
