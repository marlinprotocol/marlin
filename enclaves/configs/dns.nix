# dns config
# set up systemd-resolved with DoT
{...}: {
  marlin.kernel.fragments = ["network"];
  marlin.systemd.packageOptions = {
    withNetworkd = true;
    withResolved = true;
    withOpenSSL = true;
    withNss = true;
  };
  networking.useNetworkd = true;
  networking.useDHCP = true;
  systemd.network.enable = true;

  # set up systemd-resolved
  services.resolved = {
    # enable systemd-resolved
    enable = true;
    # enable for all domains
    domains = ["~."];
    # disable fallbacks to prevent bypass
    fallbackDns = [];
    llmnr = "false";
    # enable DoT to prevent MITM
    dnsovertls = "true";
  };
  # set up nameservers
  networking.nameservers = [
    # Quad9
    "9.9.9.9#dns.quad9.net"
    # Cloudflare
    "1.1.1.1#cloudflare-dns.com"
    "1.0.0.1#cloudflare-dns.com"
    # Google
    "8.8.8.8#dns.google"
    "8.8.4.4#dns.google"
  ];
}
