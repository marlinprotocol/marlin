{
  nixpkgs,
  systemConfig,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
in
  if system != "x86_64-linux"
  then {}
  else let
    kernelVersion = "6.18.28";
    lib = pkgs.lib;

    linuxSrc = pkgs.fetchurl {
      url = "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${kernelVersion}.tar.xz";
      hash = "sha256-82B4lINYbPiiC0qyv/526ta2LA2x7rDZFylEVsTXe3Q=";
    };

    defaultFragments = ["base" "disk-ro" "network"];
    kernelConfigArch = "x86_64";
    kernelMakeArch = "x86";
    fragmentDir = ./fragments;
    fragmentEntries = builtins.readDir fragmentDir;
    kconfigSuffix = ".kconfig";
    knownKernelFragmentArchs = [kernelConfigArch];
    requiredOptionPrefix = "# required: ";

    fragmentPath = fileName: fragmentDir + "/${fileName}";
    removeSuffix = suffix: string:
      builtins.substring 0 ((builtins.stringLength string) - (builtins.stringLength suffix)) string;
    removePrefix = prefix: string:
      builtins.substring (builtins.stringLength prefix) (builtins.stringLength string) string;
    words = string:
      builtins.filter (word: word != "") (lib.splitString " " string);
    fragmentBaseName = fileName: removeSuffix kconfigSuffix fileName;
    isArchSpecificKconfigFile = fileName:
      lib.any
      (arch: lib.hasSuffix "-${arch}" (fragmentBaseName fileName))
      knownKernelFragmentArchs;

    knownFragments = map fragmentBaseName (
      builtins.filter
      (
        fileName:
          fragmentEntries.${fileName}
          == "regular"
          && lib.hasSuffix kconfigSuffix fileName
          && !(isArchSpecificKconfigFile fileName)
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

    fragmentFilesFor = fragment: let
      archFragment = "${fragment}-${kernelConfigArch}.kconfig";
    in
      ["${fragment}.kconfig"]
      ++ lib.optional (builtins.pathExists (fragmentPath archFragment)) archFragment;

    kernelConfigFragments =
      lib.genAttrs knownFragments (fragment: readKernelConfigFragment "${fragment}.kconfig");

    selectKernelConfigFragments = fragments: let
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
      else map readKernelConfigFragment (builtins.concatLists (map fragmentFilesFor selectedFragments));

    renderKernelConfigFragment = fragment: "# Fragment: ${fragment.fileName}\n${fragment.text}";
    renderKernelConfigFragments = fragments:
      lib.concatStringsSep "\n\n" (
        ["# Marlin green-image boot requirements on ${kernelConfigArch} QEMU."]
        ++ map renderKernelConfigFragment fragments
      )
      + "\n";
    requiredConfigOptionsForFragments = fragments:
      lib.unique (builtins.concatLists (map (fragment: fragment.requiredOptions) fragments));

    mkConfig = {fragments ? defaultFragments}: let
      selectedFragments = selectKernelConfigFragments fragments;
      marlinConfig = pkgs.writeText "marlin-qemu-kconfig-fragments.config" (
        renderKernelConfigFragments selectedFragments
      );
      requiredConfigOptions = requiredConfigOptionsForFragments selectedFragments;
      requiredConfigOptionsShell =
        lib.concatMapStringsSep " \\\n          " lib.escapeShellArg requiredConfigOptions;
      checkRequiredConfigOptions = lib.optionalString (requiredConfigOptions != []) ''
        for option in \
          ${requiredConfigOptionsShell}
        do
          grep -q "^$option=y$" "$KCONFIG_CONFIG"
        done
      '';
    in
      pkgs.runCommand "marlin-qemu-linux-${kernelVersion}.config" {
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

        cp "$KCONFIG_CONFIG" "$out"
      '';

    mkKernel = {
      fragments ? defaultFragments,
      configfile ? mkConfig {inherit fragments;},
    }:
      pkgs.linuxKernel.manualConfig {
        pname = "marlin-qemu-linux";
        version = kernelVersion;
        modDirVersion = kernelVersion;
        src = linuxSrc;
        inherit configfile;
        allowImportFromDerivation = true;
        extraMeta = {
          description = "Minimal x86_64 QEMU Linux kernel for Marlin green images";
        };
      };

    config = mkConfig {fragments = defaultFragments;};

    kernel = mkKernel {
      fragments = defaultFragments;
      configfile = config;
    };
  in {
    default = kernel;
    inherit
      config
      defaultFragments
      kernel
      kernelConfigFragments
      kernelVersion
      knownFragments
      linuxSrc
      mkConfig
      mkKernel
      ;
  }
