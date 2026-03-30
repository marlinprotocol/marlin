{
  nixpkgs,
  systemConfig,
  crane,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
  crane' = crane.mkLib pkgs;
  commonArgs = {
    strictDeps = true;
    doCheck = false;
    # DOES NOT run the check command
    # short circuits it by running the true command instead
    cargoCheckCommand = "true";

    src =
      pkgs.lib.cleanSourceWith {
        src = pkgs.lib.cleanSource ./.;
        # include the sql migrations that get built into the binary
        filter = path: type: (builtins.match ".*sql$" path != null) || (crane'.filterCargoSources path type);
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
