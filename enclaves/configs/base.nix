# base config
# build as minimal an image as possible
{
  config,
  lib,
  modulesPath,
  pkgs,
  ...
}: {
  disabledModules = [
    # This nixpkgs revision does not expose services.logind.enable. Drop the
    # module so it cannot add logind/user-session units while the runtime
    # systemd is built without logind.
    "system/boot/systemd/logind.nix"
  ];

  # nixos has good presets to get started
  imports = [
    # systemd config
    (./. + "/systemd.nix")
    # kernel config
    (./. + "/kernel.nix")
    # use the minimal profile as the starting point
    "${modulesPath}/profiles/minimal.nix"
    # it will not really be interactive
    "${modulesPath}/profiles/headless.nix"
    # trim bash, perl, and anything which needs them
    "${modulesPath}/profiles/bashless.nix"
    # bashless.nix includes perlless.nix.
    # "${modulesPath}/profiles/perlless.nix"
    # build as a one-shot appliance since it will never get updated
    "${modulesPath}/profiles/image-based-appliance.nix"
  ];

  marlin.kernel.fragments = ["base"];
  marlin.systemd.packageOptions = {
    # Keep the runtime manager, not just libsystemd/libudev.
    buildLibsOnly = false;

    # TPM2 support is required by the base enclave image.
    withTpm2Tss = true;
    # Required by TPM-related systemd code.
    withOpenSSL = true;
    # NixOS account setup uses systemd-sysusers integration.
    withSysusers = true;
    # Keep seccomp hardening for systemd services.
    withLibseccomp = true;
    # NixOS' udev module unconditionally builds and links udev/hwdb.bin.
    withHwdb = true;
    # NixOS PAM service definitions still reference pam_systemd.so.
    withPam = true;
    # Keep compression support for journal/runtime compatibility.
    withCompression = true;
  };

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
  boot.initrd.systemd.contents = {
    "/lib".source = lib.mkForce (pkgs.runCommand "empty-initrd-lib" {} ''
      mkdir -p "$out"
    '');
    "/etc/modules-load.d/nixos.conf".enable = false;
    "/etc/sysctl.d/nixos.conf".enable = false;
    "/etc/modprobe.d/systemd.conf".enable = false;
    "/etc/modprobe.d/ubuntu.conf".enable = false;
    "/etc/modprobe.d/debian.conf".enable = false;
  };
  # Keep the initrd compressor aligned with the kernel decompressor enabled in
  # the base kernel fragment.
  boot.initrd.compressor = "zstd";

  systemd.coredump.enable = false;
  systemd.oomd.enable = false;
  systemd.services.systemd-timedated.enable = false;
  systemd.services.systemd-update-utmp.enable = false;
  services.timesyncd.enable = false;
  systemd.suppressedSystemUnits = [
    # NixOS' base upstream-unit list includes this even when systemd-nspawn is
    # not built.
    "systemd-nspawn@.service"
    "systemd-modules-load.service"
    "kmod-static-nodes.service"
    "modprobe@.service"
  ];

  # Disable storage features that are useful on general NixOS systems but not
  # needed for these sealed dm-verity images.
  services.lvm.enable = false;
  services.fstrim.enable = false;
  # Covered by bashless.nix; kept here as a record of the previous explicit trim.
  # boot.bcache.enable = false;
  boot.initrd.services.bcache.enable = false;
  # Covered by bashless.nix; kept here as a record of the previous explicit trim.
  # programs.fuse.enable = false;
  # console.enable = false;

  # The image does not need a system bus; disabling it also avoids pulling in
  # the separate systemd-minimal package through dbus.
  services.dbus.enable = lib.mkForce false;

  # state version
  system.stateVersion = "25.11";

  # forbid dependencies to ensure they truly do not get included
  # mainly to reduce image bloat
  # see bashless.nix and perlless.nix for examples
  system.forbiddenDependenciesRegexes = [
    # bashless.nix and perlless.nix forbid these too; keep them here to make
    # the image policy explicit.
    "bash"
    "perl"
    "python"
  ];

  # set a higher log level for better visibility into the boot process
  # not enabled by default to avoid exposing secrets
  # boot.initrd.verbose = true;
  # boot.consoleLogLevel = 4;

  # the appliance profile causes us to be locked out and nix does not like it
  # set this to tell nix we know what we are doing
  users.allowNoPasswordLogin = true;

  # /usr is a read-only verity mount in this image, so nixos-init cannot create
  # the conventional /usr/bin/env compatibility symlink during switch-root.
  environment.usrbinenv = null;

  # Covered by bashless.nix; kept here as a record of the previous explicit trim.
  # programs.bash.completion.enable = false;
  # disable nano
  programs.nano.enable = false;
  # disable sudo
  security.sudo.enable = false;
  # disable pam_p11 module
  security.pam.p11.enable = false;

  # extra kernel params
  # ref: https://github.com/aws/nitrotpm-attestation-samples/blob/main/nix/image/verity.nix#L82
  boot.kernelParams = [
    # panic=X option already set by headless.nix
    # boot.panic_on_fail option already set by headless.nix
    "lockdown=1"
    "console=ttyS0,115200n8"
    # "console=tty0"
    "random.trust_cpu=on"
    "tpm_crb.force=1"
    "systemd.show_status=true"
    "systemd.status_unit_format=name"
  ];
}
