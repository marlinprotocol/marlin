# dns config
# Enable stage-2 networking for enclave images that need outbound DNS, and
# route name resolution through systemd-resolved with strict DNS-over-TLS.
{...}: {
  # DNS requires the network-capable kernel fragment and matching systemd
  # binaries. withNss provides libnss_resolve.so so normal libc hostname
  # lookups use resolved; withOpenSSL is required for DNS-over-TLS.
  marlin.kernel.fragments = ["network"];
  marlin.systemd.packageOptions = {
    withNetworkd = true;
    withResolved = true;
    withOpenSSL = true;
    withNss = true;
  };

  # Base images intentionally disable the stage-2 network stack. This fragment
  # opts back into networkd-managed DHCP for images that need DNS.
  networking.useNetworkd = true;
  networking.useDHCP = true;
  systemd.network.enable = true;

  # Run systemd-resolved as the only local resolver entry point. The NixOS
  # resolved module points /etc/resolv.conf at resolved's local stub, so libc
  # clients go through the policy below instead of reading provider DNS
  # addresses directly.
  services.resolved = {
    enable = true;

    settings.Resolve = {
      # Route the DNS root through the global resolvers below. This keeps normal
      # lookups on the explicit DoT resolver set instead of DHCP-provided link
      # resolvers winning through the default-route path.
      Domains = ["~."];

      # Do not fall back to systemd's compiled-in public resolvers if the
      # configured DoT resolvers fail.
      FallbackDNS = [];

      # LLMNR is local multicast name resolution, separate from unicast DNS and
      # not protected by DNS-over-TLS. Enclave images should not answer or issue
      # those link-local hostname queries.
      LLMNR = "false";

      # Strict mode fails closed if a resolver does not support DNS-over-TLS or
      # presents a certificate that does not match its configured server name.
      DNSOverTLS = "true";
    };
  };

  # Pin each resolver IP to its TLS server name. The name after # is used for
  # certificate validation and SNI; without it, validation relies on the IP
  # address being present in the resolver certificate.
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
