# Image for limiter
{
  nixpkgs,
  systemConfig,
  limiter-ebpf,
  limiter-server,
}: let
  modulesPath = "${nixpkgs}/nixos/modules";
  nixosConfig = {config, ...}: {
    imports = [
      # use the minimal profile as the starting point
      "${modulesPath}/profiles/minimal.nix"
      # it will not really be interactive
      "${modulesPath}/profiles/headless.nix"
      # trim perl and anything which needs perl
      "${modulesPath}/profiles/perlless.nix"
      # build as a one-shot appliance since it will never get updated
      "${modulesPath}/profiles/image-based-appliance.nix"
      # build as a qemu guest so virtualization modules are included
      "${modulesPath}/profiles/qemu-guest.nix"
      # image.repart support
      "${modulesPath}/image/repart.nix"

      # enclave services
      limiter-ebpf
      limiter-server
    ];

    # state version
    system.stateVersion = "25.11";

    # image id
    system.image.id = "marlin-cvm-limiter";
    # image version
    system.image.version = "v0.1.0";

    # the appliance profile causes us to be locked out and nix does not like it
    # set this to tell nix we know what we are doing
    users.allowNoPasswordLogin = true;

    # extra kernel params
    boot.kernelParams = [
      "console=ttyS0,115200n8"
      "random.trust_cpu=on"
    ];

    # uki config
    boot.loader.systemd-boot.enable = false;

    # repart config
    image.repart.name = config.system.image.id;
    image.repart.version = config.system.image.version;
    image.repart.partitions = {
      "10-esp" = {
        contents = {
          "/EFI/BOOT/BOOT${systemConfig.efi_arch}.EFI".source = "${config.system.build.uki}/${config.system.boot.loader.ukiFile}";
        };
        repartConfig = {
          Label = "ESP";
          Type = "esp";
          Format = "vfat";
        };
      };
      "20-root" = {
        storePaths = [config.system.build.toplevel];
        repartConfig = {
          Label = "nixos";
          Type = "root";
          Format = "ext4";
          Minimize = "guess";
        };
      };
    };

    # filesystem config
    fileSystems = {
      "/boot" = {
        device = "/dev/disk/by-label/ESP";
        fsType = "vfat";
      };
      "/" = {
        device = "/dev/disk/by-label/nixos";
        fsType = "ext4";
        autoResize = true;
      };
    };

    # enable ssh
    services.openssh = {
      enable = true;
      settings = {
        PermitRootLogin = "prohibit-password";
        PasswordAuthentication = false;
      };
    };

    # disable internal firewall
    networking.firewall.enable = false;
    # enable forwarding
    boot.kernel.sysctl = {
      "net.ipv4.ip_forward" = 1;
      # "net.ipv6.conf.all.forwarding" = 1;
    };

    # switch to systemd-networkd for PBR
    networking.useNetworkd = true;
    systemd.network.enable = true;

    # configure network interfaces
    # one interface for the control plane with the server
    # one interface for the data place with forwarding
    systemd.network = {
      networks = {
        # Device Index 0 - Primary/App
        "10-ens5-app" = {
          matchConfig.Name = "ens5";
          DHCP = "ipv4";
          dhcpV4Config.RouteMetric = 100;
        };

        # Device Index 1 - Secondary/Forwarding
        "10-ens6-fwd" = {
          matchConfig.Name = "ens6";
          DHCP = "ipv4";
          dhcpV4Config = {
            RouteTable = 100;
            RouteMetric = 200;
            UseDNS = false;
          };
          routingPolicyRules = [
            {
              RoutingPolicyRule = {
                IncomingInterface = "ens6";
                Table = 100;
                Priority = 1000;
              };
            }
          ];
        };
      };
    };

    # enable cloud-init
    services.cloud-init.enable = true;
    services.cloud-init.network.enable = true;

    systemd.services.limiter-server.after = ["limiter-ebpf.service"];
  };
  nixosSystem = nixpkgs.lib.nixosSystem {
    system = systemConfig.system;
    modules = [nixosConfig];
  };
in {
  default = nixosSystem.config.system.build.image;
}
