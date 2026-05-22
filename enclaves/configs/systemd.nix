# systemd config
# build the runtime systemd package from explicitly selected features
{
  config,
  lib,
  pkgs,
  ...
}: let
  runtimeSystemdMinimalOptions = {
    buildLibsOnly = false;
    withAcl = false;
    withAnalyze = false;
    withApparmor = false;
    withAudit = false;
    withBootloader = false;
    withCompression = false;
    withCoredump = false;
    withCryptsetup = false;
    withDocumentation = false;
    withEfi = false;
    withFido2 = false;
    withFirstboot = false;
    withGcrypt = false;
    withHomed = false;
    withHostnamed = false;
    withHwdb = false;
    withImportd = false;
    withKernelInstall = false;
    withKexectools = false;
    withKmod = false;
    withLibarchive = false;
    withLibBPF = false;
    withLibidn2 = false;
    withLibseccomp = false;
    withLocaled = false;
    withLogind = false;
    withLogTrace = false;
    withMachined = false;
    withNetworkd = false;
    withNss = false;
    withNspawn = false;
    withOomd = false;
    withOpenSSL = false;
    withPasswordQuality = false;
    withPam = false;
    withPCRE2 = false;
    withPolkit = false;
    withPortabled = false;
    withQrencode = false;
    withRemote = false;
    withRepart = false;
    withResolved = false;
    withSelinux = false;
    withShellCompletions = false;
    withSysusers = false;
    withSysupdate = false;
    withTests = false;
    withTimedated = false;
    withTimesyncd = false;
    withTpm2Tss = false;
    withUkify = false;
    withUserDb = false;
    withUtmp = false;
    withVConsole = false;
    withVmspawn = false;
  };
  runtimeSystemd = pkgs.systemd.override config.marlin.systemd.packageOptions;
in {
  disabledModules = [
    # This nixpkgs revision does not expose services.logind.enable. Drop the
    # module so it cannot add logind/user-session units while the runtime
    # systemd is built without logind.
    "system/boot/systemd/logind.nix"
  ];

  options.marlin.systemd.packageOptions = lib.mkOption {
    type = with lib.types; attrsOf bool;
    default = {};
    description = ''
      Arguments passed to pkgs.systemd.override for the stage-2 runtime systemd
      package. Config fragments should enable the with* flags they require.
    '';
  };

  config = {
    marlin.systemd.packageOptions = lib.mkMerge [
      (lib.mapAttrs (_: lib.mkDefault) runtimeSystemdMinimalOptions)
      {
        # Keep the runtime manager, not just libsystemd/libudev.
        buildLibsOnly = false;

        # TPM2 support is required by the base enclave image.
        withTpm2Tss = true;
        # Required by TPM-related systemd code.
        withOpenSSL = true;
        # Keep module-loading support for udev/modules-load until the boot path is
        # proven not to need it.
        withKmod = true;
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
      }
    ];

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
  };
}
