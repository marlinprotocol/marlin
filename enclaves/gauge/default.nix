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

    src = crane'.cleanCargoSource ./.;
  };
  deps = crane'.buildDepsOnly commonArgs;
in {
  default = crane'.buildPackage (commonArgs
    // {
      cargoArtifacts = deps;
    });
}
