# no kernel modules config
# Enclave images use kernels with all required drivers built in and loadable
# kernel module support disabled. Remove the NixOS plumbing that would otherwise
# collect module closures, write modprobe config, or start module-loading units.
{
  config,
  lib,
  pkgs,
  ...
}: {
  # Kernel/module-list policy.
  # NixOS defaults add a broad initrd module list. The custom kernels do not
  # ship loadable modules, so resolving those defaults would fail and would hide
  # accidental module dependencies.
  boot.initrd.includeDefaultModules = lib.mkForce false;

  # Imported modules may add "loop", "atkbd", filesystem drivers, or other
  # module names. Force all explicit stage-1 and stage-2 load lists empty.
  boot.kernelModules = lib.mkForce [];
  boot.initrd.availableKernelModules = lib.mkForce [];
  boot.initrd.kernelModules = lib.mkForce [];

  # Do not install kmod, generate /etc/modprobe.d, or write /proc/sys/kernel/modprobe
  # during activation. There should be no userspace modprobe path in the image.
  boot.modprobeConfig.enable = lib.mkForce false;

  # Fail if a selected kernel ever grows loadable module support. Required
  # enclave drivers must be built in instead.
  system.requiredKernelConfig = with config.lib.kernelConfig; [
    (isDisabled "MODULES")
  ];

  # Stage-2 runtime cleanup.
  # kernel.nix still declares modules-load.d/nixos.conf and systemd's upstream
  # unit set still includes module-loading units. Disable both paths so stage 2
  # has no module loader service even if another module adds dependencies later.
  environment.etc."modules-load.d/nixos.conf".enable = lib.mkForce false;
  systemd.suppressedSystemUnits = [
    "systemd-modules-load.service"
    "kmod-static-nodes.service"
    "modprobe@.service"
  ];

  # Stage-1 initrd unit cleanup.
  # The systemd initrd module imports these upstream units independently of the
  # kernel config. Suppress the unit files and the systemd-modules-load binary.
  boot.initrd.systemd.suppressedUnits = [
    "systemd-modules-load.service"
    "kmod-static-nodes.service"
    "modprobe@.service"
  ];
  boot.initrd.systemd.suppressedStorePaths = [
    "${config.boot.initrd.systemd.package}/lib/systemd/systemd-modules-load"
  ];

  # Stage-1 udev compatibility.
  # Do not set boot.hardwareScan=false here. On this nixpkgs revision, the
  # systemd initrd udev builder copies 80-drivers.rules and then tries to add a
  # /dev/null replacement for it, which fails if the rule path exists. Provide an
  # empty 80-drivers.rules in the initrd systemd package instead: udev can build
  # its rule set, but there are no modprobe rules to execute.
  marlin.systemd.initrdPackagePostInstall = lib.mkAfter ''
    mkdir -p "$out/lib/udev/rules.d"
    : > "$out/lib/udev/rules.d/80-drivers.rules"
  '';

  # Stage-1 initrd file-tree cleanup.
  # With CONFIG_MODULES unset, this nixpkgs revision still enters the branch that
  # copies the module closure and modprobe snippets into the systemd initrd.
  # Force /lib to an empty directory and remove the generated module files.
  boot.initrd.systemd.contents = {
    # Prevent makeInitrdNG from copying config.system.build.modulesClosure/lib.
    "/lib".source = lib.mkForce (pkgs.runCommand "empty-initrd-lib" {} ''
      mkdir -p "$out"
    '');

    # These files are only meaningful when module loading exists.
    "/etc/modules-load.d/nixos.conf".enable = false;
    "/etc/sysctl.d/nixos.conf".enable = false;
    "/etc/modprobe.d/systemd.conf".enable = false;
    "/etc/modprobe.d/ubuntu.conf".enable = false;
    "/etc/modprobe.d/debian.conf".enable = false;
  };
}
