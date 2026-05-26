# Read-only disk layout for green enclave images.
#
# The image boots from a small ESP, mounts a dm-verity protected EROFS /usr,
# and uses tmpfs for the writable root filesystem. The Nix store then lives
# under /usr and is bind-mounted back to /nix/store, so runtime mutation is
# temporary while system binaries stay measured and verified.
{
  config,
  pkgs,
  lib,
  modulesPath,
  systemConfig,
  ...
}: {
  marlin.kernel.fragments = ["disk-ro"];

  # Import NixOS' repart image builder. This also brings in the verityStore
  # helper used below to build the intermediate image, derive the /usr roothash,
  # and inject the final UKI into the ESP.
  imports = [
    "${modulesPath}/image/repart.nix"
  ];

  # Runtime mount layout. / is deliberately tmpfs so state does not persist
  # across boots. systemd-veritysetup creates /dev/mapper/usr from the UKI's
  # embedded usrhash; that verified EROFS partition carries the store closure.
  # NixOS treats /, /usr, and /nix/store as boot-needed mount points, so these
  # entries are mounted in the initrd before stage 2 starts.
  #
  # NOTE: a direct overlay mount on / would be cleaner because it
  # would avoid special-casing paths under /usr. That did not boot reliably in
  # earlier experiments, so the current layout verifies /usr and bind-mounts
  # /usr/nix/store back to /nix/store. If future root-overlay experiments work,
  # this is the section to revisit; until then, services that need immutable
  # paths outside /usr may require additional bind mounts.
  # ref: https://github.com/aws/nitrotpm-attestation-samples/blob/main/nix/image/verity.nix#L19
  fileSystems = {
    "/" = {
      fsType = "tmpfs";
      options = ["mode=0755"];
    };

    "/usr" = {
      device = "/dev/mapper/usr";
      options = ["ro"];
      fsType = "erofs";
    };

    "/nix/store" = {
      device = "/usr/nix/store";
      options = ["bind"];
    };
  };

  # /usr is a read-only verity mount, so nixos-init cannot create the
  # conventional /usr/bin/env compatibility symlink during switch-root.
  environment.usrbinenv = null;

  # Runtime toplevel stored on the verified /usr partition.
  #
  # config.system.build.toplevel is also the bootloader-facing system closure:
  # it references the kernel, initrd, kernel modules, and other boot artifacts.
  # The UKI on the ESP already carries the kernel and initrd, so using the
  # normal toplevel as the repart store path would duplicate those artifacts in
  # the verified EROFS partition.
  #
  # Build a smaller stage-2 toplevel instead. The UKI command line points init=
  # at this output, which keeps the runtime paths NixOS expects while omitting
  # the boot artifacts that are already represented by the UKI.
  system.build.marlinRuntimeToplevel = let
    toplevel = config.system.build.toplevel;
    copiedFiles = [
      # bashless/image-based-appliance toplevels do not emit activation or
      # prepare-root scripts. Keep these disabled unless runtime activation is
      # intentionally brought back.
      # "activate"
      "extra-dependencies"
      "init"
      "init-interface-version"
      "kernel-params"
      "nixos-version"
      # "prepare-root"
      "system"
    ];
    linkedPaths = [
      "etc"
      "etc-basedir"
      "etc-metadata-image"
      "firmware"
      "sw"
      "systemd"
    ];
  in
    pkgs.runCommand "marlin-runtime-toplevel" {} ''
      mkdir -p "$out/specialisation"

      for file in ${toString copiedFiles}; do
        cp -a "${toplevel}/$file" "$out/$file"
      done

      for path in ${toString linkedPaths}; do
        ln -s "$(readlink "${toplevel}/$path")" "$out/$path"
      done

      # If activation or prepare-root return, rewrite their self-references so
      # they point at this runtime toplevel rather than the original toplevel.
      # substituteInPlace "$out/activate" \
      #   --replace-fail "${toplevel}" "$out"
      # substituteInPlace "$out/prepare-root" \
      #   --replace-fail "${toplevel}" "$out"
    '';

  # GPT partition layout.
  #
  # - 00-esp: firmware-readable FAT partition holding the UKI.
  # - 10-store-verity: dm-verity hash tree for the read-only store partition.
  # - 20-store: EROFS data partition, exposed by the Discoverable Partitions
  #   Specification as /usr and populated with the custom runtime toplevel.
  image.repart.partitions = {
    "00-esp".repartConfig = {
      Label = "esp";
      Type = "esp";
      Format = "vfat";
      SizeMinBytes = "128M";
      SizeMaxBytes = "128M";
    };

    "10-store-verity".repartConfig = {
      Label = "store-verity";
      Type = "usr-${systemConfig.repart_arch}-verity";
      Verity = "hash";
      VerityMatchKey = "store";
      Minimize = "best";
    };

    "20-store" = {
      # The image should contain the toplevel that the UKI actually boots.
      storePaths = lib.mkForce [config.system.build.marlinRuntimeToplevel];
      repartConfig = {
        Label = "store";
        Type = "usr-${systemConfig.repart_arch}";
        Format = "erofs";
        Verity = "data";
        VerityMatchKey = "store";
        Minimize = "best";
      };
    };
  };
  # NOTE: Experiment with this \_(-_-)_/
  # image.repart.sectorSize = 4096;

  # Enable NixOS' verity-store image flow: first build the /usr data/hash
  # partitions, then build a UKI with the resulting usrhash, then inject that
  # UKI into the final ESP. The fallback path is required for firmware that
  # boots the default removable-media location rather than /EFI/Linux.
  image.repart.verityStore = {
    enable = true;
    ukiPath = "/EFI/BOOT/BOOT${systemConfig.efi_arch}.EFI";
  };

  # Replace verityStore's UKI builder with the two Marlin-specific changes:
  # use marlinRuntimeToplevel for init=, and strip .osrel from the final UKI so
  # the measurement matches the verifier expectations.
  system.build.uki = lib.mkOverride 90 (
    let
      inherit (config.system.boot.loader) ukiFile;

      # Replicate upstream verityStore's cmdline, but point init= at the custom
      # runtime toplevel that is actually included in the EROFS partition.
      cmdline = "init=${config.system.build.marlinRuntimeToplevel}/init ${toString config.boot.kernelParams}";

      partitionTypes = {
        usr-verity = "usr-${systemConfig.repart_arch}-verity";
      };
    in
      pkgs.runCommand ukiFile
      {
        nativeBuildInputs = [
          pkgs.buildPackages.jq
          pkgs.buildPackages.systemdUkify
          pkgs.llvm # Added for llvm-objcopy
        ];
      }
      ''
        mkdir -p $out

        # Extract the /usr roothash from the intermediate repart output.
        usrhash=$(jq -r \
          '.[] | select(.type=="${partitionTypes.usr-verity}") | .roothash' \
          ${config.system.build.intermediateImage}/repart-output.json
        )

        # Embed usrhash= so systemd-veritysetup-generator can create
        # /dev/mapper/usr in the initrd before /usr is mounted.
        ukify build \
            --config=${config.boot.uki.configFile} \
            --cmdline="${cmdline} usrhash=$usrhash" \
            --output="$out/${ukiFile}"

        # Drop os-release metadata from the PE image; the attestation tooling
        # measures the resulting UKI bytes.
        ${pkgs.llvm}/bin/llvm-objcopy --remove-section .osrel "$out/${ukiFile}"
      ''
  );

  # Boot parameters for the verified /usr flow. Keep the verity generator
  # explicitly enabled, panic on detected /usr corruption, and disable GPT auto
  # mounting so only the declarative mounts above decide what gets attached.
  boot.kernelParams = [
    "systemd.verity=1"
    "systemd.verity_usr_options=panic-on-corruption"
    "systemd.gpt_auto=0"
  ];
}
