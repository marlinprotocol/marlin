# Build separate systemd packages for the runtime system and the initrd.
#
# Enclave images start from a minimal systemd feature set: optional nixpkgs
# systemd override flags are disabled here, and config fragments opt back into
# the exact package features required by the units and tools they add.
{
  config,
  lib,
  pkgs,
  ...
}: let
  # Shared deny-by-default baseline for pkgs.systemd.override arguments. Keeping
  # the flags explicit makes the package closure stable when nixpkgs changes
  # its systemd defaults, and makes feature opt-ins visible in the fragments
  # that need them.
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
  # Runtime and initrd use the same minimal baseline today, but keep separate
  # names so stage-specific defaults can diverge without changing callers.
  runtimeSystemdMinimalOptions = systemdMinimalOptions;
  initrdSystemdMinimalOptions = systemdMinimalOptions;

  # Stage-2 systemd is built from the merged packageOptions below. Those
  # options describe package build features only; service enablement still lives
  # in the normal NixOS module options for each fragment.
  runtimeSystemd = pkgs.systemd.override config.marlin.systemd.packageOptions;

  # Stage-1 gets its own systemd build because the initrd has a smaller and
  # different dependency surface. The postInstall hook is appended rather than
  # replaced so fragments can add initrd-only compatibility fixes while keeping
  # nixpkgs' normal install work.
  initrdSystemd = (pkgs.systemd.override config.marlin.systemd.initrdPackageOptions)
    .overrideAttrs (oldAttrs: {
    postInstall =
      (oldAttrs.postInstall or "")
      + "\n"
      + config.marlin.systemd.initrdPackagePostInstall;
  });
in {
  # Public knobs used by enclave fragments to opt into systemd features.
  # Values map directly to pkgs.systemd.override arguments.
  options.marlin.systemd.packageOptions = lib.mkOption {
    type = with lib.types; attrsOf bool;
    default = {};
    description = ''
      Arguments passed to pkgs.systemd.override for the stage-2 runtime systemd
      package. Config fragments should enable the with* flags they require.
    '';
  };

  # Same override surface as packageOptions, but for the initrd systemd build.
  options.marlin.systemd.initrdPackageOptions = lib.mkOption {
    type = with lib.types; attrsOf bool;
    default = {};
    description = ''
      Arguments passed to pkgs.systemd.override for the stage-1 initrd systemd
      package. Config fragments should enable the with* flags they require.
    '';
  };

  # Escape hatch for rare initrd package patches that must live beside the
  # initrd systemd derivation instead of in the NixOS module graph.
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
    # Apply the minimal package baselines as mkDefault values. That keeps the
    # shared systemd packages small and predictable, while still allowing any
    # importing fragment to set a required flag to true.
    marlin.systemd.packageOptions =
      lib.mapAttrs (_: lib.mkDefault) runtimeSystemdMinimalOptions;
    marlin.systemd.initrdPackageOptions =
      lib.mapAttrs (_: lib.mkDefault) initrdSystemdMinimalOptions;

    # Install the custom stage-2 systemd package selected by the feature flags
    # above.
    systemd.package = runtimeSystemd;

    # Use the initrd-specific systemd package for stage 1. Its feature set is
    # controlled separately from the broader runtime package above.
    boot.initrd.systemd.package = initrdSystemd;
  };
}
