# systemd config
# build the runtime systemd package from explicitly selected features
{
  config,
  lib,
  pkgs,
  ...
}: let
  systemdMinimalOptions = {
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
  runtimeSystemdMinimalOptions = systemdMinimalOptions;
  initrdSystemdMinimalOptions = systemdMinimalOptions;
  runtimeSystemd = pkgs.systemd.override config.marlin.systemd.packageOptions;
  initrdSystemd = (pkgs.systemd.override config.marlin.systemd.initrdPackageOptions)
    .overrideAttrs (oldAttrs: {
    postInstall =
      (oldAttrs.postInstall or "")
      + "\n"
      + config.marlin.systemd.initrdPackagePostInstall;
  });
in {
  options.marlin.systemd.packageOptions = lib.mkOption {
    type = with lib.types; attrsOf bool;
    default = {};
    description = ''
      Arguments passed to pkgs.systemd.override for the stage-2 runtime systemd
      package. Config fragments should enable the with* flags they require.
    '';
  };

  options.marlin.systemd.initrdPackageOptions = lib.mkOption {
    type = with lib.types; attrsOf bool;
    default = {};
    description = ''
      Arguments passed to pkgs.systemd.override for the stage-1 initrd systemd
      package. Config fragments should enable the with* flags they require.
    '';
  };

  options.marlin.systemd.initrdPackagePostInstall = lib.mkOption {
    type = lib.types.lines;
    default = "";
    description = ''
      Shell commands appended to the stage-1 initrd systemd package postInstall.
      Config fragments can use this for package-local compatibility patches
      without replacing the shared package override.
    '';
  };

  config = {
    marlin.systemd.packageOptions =
      lib.mapAttrs (_: lib.mkDefault) runtimeSystemdMinimalOptions;
    marlin.systemd.initrdPackageOptions =
      lib.mapAttrs (_: lib.mkDefault) initrdSystemdMinimalOptions;

    # NOTE: perlless.nix also sets initrd to be systemd based
    # ensure the setup is according to that
    systemd.package = runtimeSystemd;
    # The initrd mounts the dm-verity protected store and keeps only the
    # systemd features required for that stage.
    boot.initrd.systemd.package = initrdSystemd;
  };
}
