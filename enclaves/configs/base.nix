# base config
# build as minimal an image as possible
{
  config,
  lib,
  modulesPath,
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
    # no kernel modules config
    (./. + "/no-kernel-modules.nix")
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
  marlin.systemd.initrdPackageOptions = {
    # Keep the initrd manager, not just libsystemd/libudev.
    buildLibsOnly = false;

    # The initrd mounts the dm-verity protected store via systemd-veritysetup.
    withCryptsetup = true;
    # Keep EFI support so systemd's initrd generators remain available while
    # systemd-boot stays disabled by the shared minimal defaults.
    withEfi = true;
    # NixOS' initrd udev path generation expects udev/hwdb support.
    withHwdb = true;
    # Keep seccomp hardening for initrd systemd services.
    withLibseccomp = true;
    # Match the zstd initrd compressor used by the base kernel fragment.
    withCompression = true;
  };

  # NixOS includes this unconditionally in the systemd initrd unit set. The
  # enclave initrd does not need a boot-status screen, and suppressing it lets
  # the initrd systemd package stay qrencode-free.
  boot.initrd.systemd.suppressedUnits = [
    "systemd-bsod.service"
  ];
  boot.initrd.systemd.suppressedStorePaths = [
    "${config.boot.initrd.systemd.package}/lib/systemd/systemd-bsod"
  ];
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
  ];
  # The kernel only keeps root cgroup support for systemd supervision. Disable
  # default per-unit accounting so systemd does not depend on optional cgroup
  # controllers or the cgroup-BPF IP accounting path.
  systemd.settings.Manager = {
    DefaultIOAccounting = false;
    DefaultIPAccounting = false;
    DefaultMemoryAccounting = false;
    DefaultTasksAccounting = false;
  };

  # Base images are offline by default. Profiles imported above prefer
  # networkd to avoid the script/dhcpcd networking stack; override that default
  # here, and let networked image fragments opt back in explicitly.
  networking.useNetworkd = lib.mkOverride 900 false;
  networking.useDHCP = lib.mkOverride 900 false;
  networking.dhcpcd.enable = lib.mkOverride 900 false;
  networking.resolvconf.enable = lib.mkOverride 900 false;
  systemd.network.enable = lib.mkOverride 900 false;
  services.resolved.enable = lib.mkOverride 900 false;

  # Disable storage features that are useful on general NixOS systems but not
  # needed for these sealed dm-verity images.
  services.lvm.enable = false;
  services.fstrim.enable = false;

  # The image does not need a system bus; disabling it also avoids pulling in
  # the separate systemd-minimal package through dbus. Keep this overridable for
  # future fragments that intentionally add D-Bus based services.
  services.dbus.enable = lib.mkOverride 90 false;

  # Reduce kernel address and log exposure inside the guest. NixOS already
  # defaults kptr_restrict to 1; use the stricter mode so even privileged
  # processes do not get raw kernel pointers from procfs-style interfaces.
  boot.kernel.sysctl."kernel.kptr_restrict" = 2;
  boot.kernel.sysctl."kernel.dmesg_restrict" = 1;

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

  # disable nano
  programs.nano.enable = false;
  # disable sudo
  security.sudo.enable = false;

  # extra kernel params
  # ref: https://github.com/aws/nitrotpm-attestation-samples/blob/main/nix/image/verity.nix#L82
  boot.kernelParams = [
    # panic=X option already set by headless.nix
    # boot.panic_on_fail option already set by headless.nix
    "console=ttyS0,115200n8"
    # "console=tty0"
    "random.trust_cpu=on"
    "tpm_crb.force=1"
    "systemd.show_status=true"
    "systemd.status_unit_format=name"
  ];
}
