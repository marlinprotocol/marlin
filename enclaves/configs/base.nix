# base config
# build as minimal an image as possible
{
  lib,
  modulesPath,
  pkgs,
  ...
}: let
  runtimeSystemd = pkgs.systemd.override {
    # Keep the runtime manager, not just libsystemd/libudev.
    buildLibsOnly = false;

    # TPM2 support is required by the image.
    withTpm2Tss = true;
    # Required by TPM-related systemd code and systemd-resolved DNS-over-TLS.
    withOpenSSL = true;
    # image-based-appliance uses systemd-networkd.
    withNetworkd = true;
    # dns.nix enables systemd-resolved with DNS-over-TLS.
    withResolved = true;
    # Keep module-loading support for udev/modules-load until the boot path is
    # proven not to need it.
    withKmod = true;
    # NixOS account setup uses systemd-sysusers integration.
    withSysusers = true;
    # Keep NSS integration until the resolved/name-service path is tested.
    withNss = true;
    # Keep seccomp hardening for systemd services.
    withLibseccomp = true;
    # NixOS' udev module unconditionally builds and links udev/hwdb.bin.
    withHwdb = true;
    # NixOS PAM service definitions still reference pam_systemd.so.
    withPam = true;
    # Keep compression support for journal/runtime compatibility.
    withCompression = true;

    # The stage-2 runtime does not mount encrypted or verity devices. The initrd
    # is pinned to full systemd below because it does need dm-verity support.
    withCryptsetup = false;

    # Not needed in the sealed appliance runtime.
    withAcl = false;
    withAnalyze = false;
    withApparmor = false;
    withAudit = false;
    withBootloader = false;
    withCoredump = false;
    withDocumentation = false;
    withEfi = false;
    withFido2 = false;
    withFirstboot = false;
    withGcrypt = false;
    withHomed = false;
    withHostnamed = false;
    withImportd = false;
    withKernelInstall = false;
    withKexectools = false;
    withLibarchive = false;
    withLibBPF = false;
    withLibidn2 = false;
    withLocaled = false;
    withLogind = false;
    withLogTrace = false;
    withMachined = false;
    withNspawn = false;
    withOomd = false;
    withPasswordQuality = false;
    withPCRE2 = false;
    withPolkit = false;
    withPortabled = false;
    withQrencode = false;
    withRemote = false;
    withRepart = false;
    withSelinux = false;
    withShellCompletions = false;
    withSysupdate = false;
    withTests = false;
    withTimedated = false;
    withTimesyncd = false;
    withUkify = false;
    withUserDb = false;
    withUtmp = false;
    withVConsole = false;
    withVmspawn = false;
  };
in {
  disabledModules = [
    # This nixpkgs revision does not expose services.logind.enable. Drop the
    # module so it cannot add logind/user-session units while the runtime
    # systemd is built without logind.
    "system/boot/systemd/logind.nix"
  ];

  # nixos has good presets to get started
  imports = [
    # allow image fragments to declare kernel feature requirements
    ({lib, ...}: {
      options.marlin.kernel.fragments = lib.mkOption {
        type = with lib.types; listOf (enum ["base" "disk-ro" "network"]);
        default = [];
        description = ''
          Kernel feature fragments required by this image configuration.
        '';
      };
    })
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

  # NOTE: perlless.nix also sets initrd to be systemd based
  # ensure the setup is according to that
  systemd.package = runtimeSystemd;
  # The initrd mounts the dm-verity protected store and therefore needs the full
  # systemd build even when the stage-2 runtime uses the reduced build above.
  boot.initrd.systemd.package = pkgs.systemd;
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

  # NixOS' systemd module requires the AF_ALG hash userspace API by default, but
  # this image does not use kernel crypto from userspace. Keep that attack
  # surface disabled while preserving the rest of system.requiredKernelConfig.
  lib.kernelConfig = lib.mkForce (let
    mkCheck = predicate: state: value: option: {
      assertion = kernelConfig: predicate kernelConfig option;
      message = "CONFIG_${option} is not ${state}!";
      configLine = "CONFIG_${option}=${value}";
    };
    isYes = mkCheck (kernelConfig: kernelConfig.isYes) "yes" "y";
    isNo = mkCheck (kernelConfig: kernelConfig.isNo) "no" "n";
    isModule = mkCheck (kernelConfig: kernelConfig.isModule) "built as a module" "m";
    defaultIsEnabled = mkCheck (kernelConfig: kernelConfig.isEnabled) "enabled" "y";
    isEnabled = option:
      if option == "CRYPTO_USER_API_HASH"
      then {
        assertion = _: true;
        message = "CONFIG_${option} is intentionally disabled!";
        configLine = "CONFIG_${option}=n";
      }
      else defaultIsEnabled option;
    isDisabled = mkCheck (kernelConfig: kernelConfig.isDisabled) "disabled" "n";
  in {
    inherit
      isYes
      isNo
      isModule
      isEnabled
      isDisabled
      ;
  });

  # The kernels used for these images build the required boot drivers in, so do
  # not ask the initrd builder to resolve NixOS' broad default module list.
  boot.initrd.includeDefaultModules = false;
  # Keep the initrd compressor aligned with the kernel decompressor enabled in
  # the base kernel fragment.
  boot.initrd.compressor = "zstd";

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
