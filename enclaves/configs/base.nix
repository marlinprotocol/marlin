# base config
# build as minimal an image as possible
{
  lib,
  modulesPath,
  ...
}: {
  # nixos has good presets to get started
  imports = [
    # systemd config
    (./. + "/systemd.nix")
    # allow image fragments to declare kernel feature requirements
    ({lib, ...}: {
      options.marlin.kernel = {
        fragments = lib.mkOption {
          type = with lib.types; listOf (enum ["base" "disk-ro" "network"]);
          default = [];
          description = ''
            Kernel feature fragments required by this image configuration.
          '';
        };
        target = lib.mkOption {
          type = lib.types.enum ["qemu" "ec2"];
          default = "ec2";
          description = ''
            Kernel target used to select target-specific Kconfig fragments.
          '';
        };
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
