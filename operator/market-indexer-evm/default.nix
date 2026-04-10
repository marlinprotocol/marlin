{
  nixpkgs,
  systemConfig,
  crane,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
  projectSrc = ./.;
  libSrc = ../indexer-framework;
  combinedSrc = pkgs.runCommand "combined-src" {} ''
    # Copy the project
    cp -r ${projectSrc} $out
    chmod -R +w $out

    # Copy the library into the project directory
    mkdir -p $out/libs/indexer-framework
    cp -r ${libSrc}/* $out/libs/indexer-framework

    # Patch Cargo.toml to point to the new library location
    substituteInPlace $out/Cargo.toml \
      --replace 'path = "../indexer-framework"' 'path = "./libs/indexer-framework"'
  '';
  crane' = crane.mkLib pkgs;
  commonArgs = {
    strictDeps = true;
    doCheck = false;
    # DOES NOT run the check command
    # short circuits it by running the true command instead
    cargoCheckCommand = "true";

    src = pkgs.lib.cleanSourceWith {
      src = pkgs.lib.cleanSource combinedSrc;
      # include the sql migrations that get built into the binary
      # include market.json abi
      filter = path: type: (builtins.match ".*sql$" path != null) || (builtins.match ".*/Market.json$" path != null) || (crane'.filterCargoSources path type);
      name = "source";
    };
    nativeBuildInputs = [pkgs.perl];
  };
  deps = crane'.buildDepsOnly commonArgs;
in {
  default = crane'.buildPackage (commonArgs
    // {
      cargoArtifacts = deps;
    });
}
