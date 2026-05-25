# kernel config
# configure kernel feature requirements for enclave images
{lib, ...}: {
  options.marlin.kernel = {
    fragments = lib.mkOption {
      type = with lib.types; listOf str;
      description = ''
        Kernel feature fragments required by this image configuration.
      '';
    };
    target = lib.mkOption {
      type = lib.types.str;
      description = ''
        Kernel target used to select target-specific Kconfig fragments.
      '';
    };
  };

  config = {
    # NixOS' systemd module requires the AF_ALG hash userspace API by default,
    # but this image does not use kernel crypto from userspace. Keep that attack
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
  };
}
