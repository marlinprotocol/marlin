# no kernel modules config
# disable runtime and initrd kernel module loading
{
  config,
  lib,
  pkgs,
  ...
}: {
  # The kernels used for these images build the required boot drivers in, so do
  # not ask the initrd builder to resolve NixOS' broad default module list.
  boot.initrd.includeDefaultModules = false;
  boot.kernelModules = [];
  boot.initrd.availableKernelModules = [];
  boot.initrd.kernelModules = [];
  boot.modprobeConfig.enable = false;
  # Do not set boot.hardwareScan=false here. On this nixpkgs revision, the
  # systemd initrd udev builder copies 80-drivers.rules and then tries to add a
  # /dev/null replacement for it, which fails if the rule path exists. Module
  # autoloading is disabled instead by building systemd without kmod and by
  # providing an empty initrd 80-drivers.rules placeholder.
  environment.etc."modules-load.d/nixos.conf".enable = false;
  boot.initrd.systemd.suppressedUnits = [
    "systemd-modules-load.service"
    "kmod-static-nodes.service"
    "modprobe@.service"
  ];
  boot.initrd.systemd.suppressedStorePaths = [
    "${config.boot.initrd.systemd.package}/lib/systemd/systemd-modules-load"
  ];
  marlin.systemd.initrdPackagePostInstall = lib.mkAfter ''
    # NixOS' initrd udev module hard-codes this standard rule into the
    # initial rule set. Keep the path valid without enabling udev/kmod
    # module autoloading.
    mkdir -p "$out/lib/udev/rules.d"
    : > "$out/lib/udev/rules.d/80-drivers.rules"
  '';
  boot.initrd.systemd.contents = {
    "/lib".source = lib.mkForce (pkgs.runCommand "empty-initrd-lib" {} ''
      mkdir -p "$out"
    '');
    "/etc/modules-load.d/nixos.conf".enable = false;
    "/etc/modprobe.d/systemd.conf".enable = false;
    "/etc/modprobe.d/ubuntu.conf".enable = false;
    "/etc/modprobe.d/debian.conf".enable = false;
  };

  systemd.suppressedSystemUnits = [
    "systemd-modules-load.service"
    "kmod-static-nodes.service"
    "modprobe@.service"
  ];
}
