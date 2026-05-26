{
  nixpkgs,
  systemConfig,
}: let
  system = systemConfig.system;
  supportedKernelArchitectures = {
    "aarch64-linux" = {
      kernelConfigArch = "arm64";
      kernelMakeArch = "arm64";
      kernelDescriptionArch = "arm64";
    };
    "x86_64-linux" = {
      kernelConfigArch = "x86_64";
      kernelMakeArch = "x86";
      kernelDescriptionArch = "x86_64";
    };
  };
in
  if !(builtins.hasAttr system supportedKernelArchitectures)
  then {}
  else let
    pkgs = nixpkgs.legacyPackages."${system}";
    kernelVersion = "7.0.10";
    lib = pkgs.lib;
    kernelArchitecture = supportedKernelArchitectures.${system};
    inherit
      (kernelArchitecture)
      kernelConfigArch
      kernelDescriptionArch
      kernelMakeArch
      ;

    linuxSrc = pkgs.fetchurl {
      url = "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-${kernelVersion}.tar.xz";
      hash = "sha256-CUl362LCDj0ZOf6BqSlYofmH8zlEblMvqGljsoBOMtw=";
    };

    knownTargets = ["qemu" "ec2"];
    fragmentDir = ./fragments;
    fragmentEntries = builtins.readDir fragmentDir;
    kconfigSuffix = ".kconfig";
    knownKernelFragmentArchs =
      lib.unique
      (map
        (systemName: supportedKernelArchitectures.${systemName}.kernelConfigArch)
        (builtins.attrNames supportedKernelArchitectures));
    requiredOptionPrefix = "# required: ";
    forbiddenConfigOptions = [
      "CONFIG_MODULES"
      "CONFIG_CRYPTO_USER_API"
      "CONFIG_CRYPTO_USER_API_HASH"
      "CONFIG_CRYPTO_USER_API_SKCIPHER"
      "CONFIG_CRYPTO_USER_API_RNG"
      "CONFIG_CRYPTO_USER_API_AEAD"
    ];

    fragmentPath = fileName: fragmentDir + "/${fileName}";
    removeSuffix = suffix: string:
      builtins.substring 0 ((builtins.stringLength string) - (builtins.stringLength suffix)) string;
    removePrefix = prefix: string:
      builtins.substring (builtins.stringLength prefix) (builtins.stringLength string) string;
    words = string:
      builtins.filter (word: word != "") (lib.splitString " " string);
    fragmentBaseName = fileName: removeSuffix kconfigSuffix fileName;
    variantSuffixes =
      (map (arch: "-${arch}") knownKernelFragmentArchs)
      ++ (map (target: "-${target}") knownTargets)
      ++ lib.concatLists (
        map
        (arch: map (target: "-${arch}-${target}") knownTargets)
        knownKernelFragmentArchs
      );
    isVariantKconfigFile = fileName:
      lib.any
      (suffix: lib.hasSuffix suffix (fragmentBaseName fileName))
      variantSuffixes;
    validateTarget = target:
      if builtins.elem target knownTargets
      then target
      else throw "Unknown kernel target: ${target}";

    knownFragments = map fragmentBaseName (
      builtins.filter
      (
        fileName:
          fragmentEntries.${fileName}
          == "regular"
          && lib.hasSuffix kconfigSuffix fileName
          && !(isVariantKconfigFile fileName)
      )
      (builtins.attrNames fragmentEntries)
    );

    requiredConfigOptionsForText = text:
      builtins.concatLists (
        map
        (line:
          if lib.hasPrefix requiredOptionPrefix line
          then words (removePrefix requiredOptionPrefix line)
          else [])
        (lib.splitString "\n" text)
      );

    readKernelConfigFragment = fileName: let
      text = builtins.readFile (fragmentPath fileName);
    in {
      inherit fileName text;
      requiredOptions = requiredConfigOptionsForText text;
    };

    fragmentFilesFor = target: fragment: let
      checkedTarget = validateTarget target;
      archFragment = "${fragment}-${kernelConfigArch}.kconfig";
      targetFragment = "${fragment}-${checkedTarget}.kconfig";
      archTargetFragment = "${fragment}-${kernelConfigArch}-${checkedTarget}.kconfig";
    in
      ["${fragment}.kconfig"]
      ++ lib.optional (builtins.pathExists (fragmentPath archFragment)) archFragment
      ++ lib.optional (builtins.pathExists (fragmentPath targetFragment)) targetFragment
      ++ lib.optional (builtins.pathExists (fragmentPath archTargetFragment)) archTargetFragment;

    selectKernelConfigFragments = {
      target,
      fragments,
    }: let
      checkedTarget = validateTarget target;
      uniqueFragments = lib.unique fragments;
      unknownFragments =
        builtins.filter
        (fragment: !(builtins.elem fragment knownFragments))
        uniqueFragments;
      selectedFragments =
        builtins.filter
        (fragment: builtins.elem fragment uniqueFragments)
        knownFragments;
    in
      if unknownFragments != []
      then throw "Unknown kernel config fragments: ${lib.concatStringsSep ", " unknownFragments}"
      else map readKernelConfigFragment (builtins.concatLists (map (fragmentFilesFor checkedTarget) selectedFragments));

    renderKernelConfigFragment = fragment: "# Fragment: ${fragment.fileName}\n${fragment.text}";
    renderKernelConfigFragments = target: fragments:
      lib.concatStringsSep "\n\n" (
        ["# Marlin green-image boot requirements on ${kernelConfigArch} ${target}."]
        ++ map renderKernelConfigFragment fragments
      )
      + "\n";
    requiredConfigOptionsForFragments = fragments:
      lib.unique (builtins.concatLists (map (fragment: fragment.requiredOptions) fragments));

    mkConfig = {
      target,
      fragments,
    }: let
      checkedTarget = validateTarget target;
      selectedFragments = selectKernelConfigFragments {
        target = checkedTarget;
        inherit fragments;
      };
      marlinConfig = pkgs.writeText "marlin-${checkedTarget}-kconfig-fragments.config" (
        renderKernelConfigFragments checkedTarget selectedFragments
      );
      requiredConfigOptions = requiredConfigOptionsForFragments selectedFragments;
      requiredConfigOptionsShell =
        lib.concatMapStringsSep " \\\n          " lib.escapeShellArg requiredConfigOptions;
      forbiddenConfigOptionsShell =
        lib.concatMapStringsSep " \\\n          " lib.escapeShellArg forbiddenConfigOptions;
      checkRequiredConfigOptions = lib.optionalString (requiredConfigOptions != []) ''
        for option in \
          ${requiredConfigOptionsShell}
        do
          grep -q "^$option=y$" "$KCONFIG_CONFIG"
        done
      '';
      checkForbiddenConfigOptions = ''
        for option in \
          ${forbiddenConfigOptionsShell}
        do
          if grep -Eq "^$option=(y|m)$" "$KCONFIG_CONFIG"; then
            echo "$option must stay disabled" >&2
            exit 1
          fi
        done
      '';
      checkNoLoadableModules = ''
        if grep -Eq "^CONFIG_.*=m$" "$KCONFIG_CONFIG"; then
          echo "Loadable kernel modules must stay disabled" >&2
          grep -E "^CONFIG_.*=m$" "$KCONFIG_CONFIG" >&2
          exit 1
        fi
      '';
    in
      pkgs.runCommand "marlin-${checkedTarget}-linux-${kernelVersion}.config" {
        src = linuxSrc;
        nativeBuildInputs = [
          pkgs.buildPackages.stdenv.cc
          pkgs.buildPackages.bc
          pkgs.buildPackages.bison
          pkgs.buildPackages.flex
          pkgs.buildPackages.perl
        ];
      } ''
        unpackPhase
        cd linux-${kernelVersion}

        export ARCH=${kernelMakeArch}
        export KCONFIG_CONFIG="$PWD/.config"

        make KCONFIG_ALLCONFIG=${marlinConfig} allnoconfig

        ${checkRequiredConfigOptions}
        ${checkForbiddenConfigOptions}
        ${checkNoLoadableModules}

        cp "$KCONFIG_CONFIG" "$out"
      '';

    mkKernel = {
      target,
      fragments,
      configfile ? mkConfig {inherit target fragments;},
    }: let
      checkedTarget = validateTarget target;
    in
      pkgs.linuxKernel.manualConfig {
        pname = "marlin-${checkedTarget}-linux";
        version = kernelVersion;
        modDirVersion = kernelVersion;
        src = linuxSrc;
        inherit configfile;
        allowImportFromDerivation = true;
        extraMeta = {
          description = "Minimal ${kernelDescriptionArch} ${checkedTarget} Linux kernel for Marlin green images";
        };
      };
  in {
    inherit
      knownFragments
      knownTargets
      mkConfig
      mkKernel
      ;
  }
