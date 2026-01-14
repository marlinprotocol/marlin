# Image for limiter
{
  nixpkgs,
  systemConfig,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages.${system};
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
      "net.ipv6.conf.all.forwarding" = 1;
    };

    # enable cloud-init
    services.cloud-init.enable = true;
    services.cloud-init.network.enable = true;

    # TODO: set up limiter
  };
  nixosSystem = nixpkgs.lib.nixosSystem {
    system = systemConfig.system;
    modules = [nixosConfig];
  };
in {
  default = nixosSystem.config.system.build.image;
}
