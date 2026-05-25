# enclave kernel config
# Define the kernel selection interface for enclave images and adapt NixOS'
# kernel requirement checks for the deliberately smaller enclave kernel config.
{lib, ...}: {
  # Enclave images choose a kernel by naming a target plus a set of Kconfig
  # fragments. The actual fragment and target validation lives in
  # enclaves/kernels/default.nix, so this module accepts plain strings and lets
  # the kernel builder remain the single source of truth.
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
    # system.requiredKernelConfig is checked through helpers under
    # lib.kernelConfig. Most helpers should behave exactly like upstream NixOS;
    # only isEnabled needs one enclave-specific exception below.
    #
    # NixOS' systemd module requires CRYPTO_USER_API_HASH for the AF_ALG hash
    # userspace API. Enclave images do not use kernel crypto from userspace, so
    # keep that API disabled while still honoring every other kernel requirement.
    #
    # This is a whole-attrset override because options.lib is typed as a shallow
    # attrsOf attrs in NixOS. A nested override of lib.kernelConfig.isEnabled
    # would not reliably replace the upstream helper.
    lib.kernelConfig = lib.mkForce (let
      # Recreate the upstream helper shape so existing requiredKernelConfig
      # checks continue to produce the same assertion messages and config lines.
      mkCheck = predicate: state: value: option: {
        assertion = kernelConfig: predicate kernelConfig option;
        message = "CONFIG_${option} is not ${state}!";
        configLine = "CONFIG_${option}=${value}";
      };

      # Unchanged upstream-style predicates.
      isYes = mkCheck (kernelConfig: kernelConfig.isYes) "yes" "y";
      isNo = mkCheck (kernelConfig: kernelConfig.isNo) "no" "n";
      isModule = mkCheck (kernelConfig: kernelConfig.isModule) "built as a module" "m";
      defaultIsEnabled = mkCheck (kernelConfig: kernelConfig.isEnabled) "enabled" "y";
      isDisabled = mkCheck (kernelConfig: kernelConfig.isDisabled) "disabled" "n";

      # Treat the systemd AF_ALG hash requirement as satisfied even though the
      # generated kernel config keeps CONFIG_CRYPTO_USER_API_HASH=n.
      isEnabled = option:
        if option == "CRYPTO_USER_API_HASH"
        then {
          assertion = _: true;
          message = "CONFIG_${option} is intentionally disabled!";
          configLine = "CONFIG_${option}=n";
        }
        else defaultIsEnabled option;
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
