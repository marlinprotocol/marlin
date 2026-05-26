# Kernel lockdown config.
{
  config,
  lib,
  ...
}: {
  options.marlin.kernel.lockdownMode = lib.mkOption {
    type = lib.types.enum ["confidentiality" "integrity"];
    default = "confidentiality";
    description = ''
      Kernel lockdown mode applied through the measured UKI command line.
    '';
  };

  config = {
    marlin.kernel.fragments = ["lockdown"];

    boot.kernelParams = [
      "lockdown=${config.marlin.kernel.lockdownMode}"
    ];
  };
}
