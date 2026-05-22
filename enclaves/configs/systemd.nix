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
  options.marlin.systemd.packageOptions = lib.mkOption {
    type = with lib.types; attrsOf bool;
    default = {};
    description = ''
      Arguments passed to pkgs.systemd.override for the stage-2 runtime systemd
      package. Config fragments should enable the with* flags they require.
    '';
  };

  config = {
    marlin.systemd.packageOptions =
      lib.mapAttrs (_: lib.mkDefault) runtimeSystemdMinimalOptions;

    # NOTE: perlless.nix also sets initrd to be systemd based
    # ensure the setup is according to that
    systemd.package = runtimeSystemd;
    # The initrd mounts the dm-verity protected store and therefore needs the full
    # systemd build even when the stage-2 runtime uses the reduced build above.
    boot.initrd.systemd.package = pkgs.systemd;
  };
}
