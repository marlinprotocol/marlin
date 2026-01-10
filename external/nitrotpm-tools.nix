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

    src = crane'.cleanCargoSource (pkgs.fetchFromGitHub {
      owner = "aws";
      repo = "NitroTPM-Tools";
      rev = "ec21ed738ba628fe460e524b3c485aed9564fe0a";
      sha256 = "sha256-ZTASHHa+LQ/hNaM0qfsaGdNwkZQQZnR9+f05DHbviLw=";
    });
    nativeBuildInputs = [
      pkgs.pkg-config
      pkgs.autoPatchelfHook
    ];
    buildInputs = [
      pkgs.tpm2-tss
      pkgs.libgcc
    ];
  };
  deps = crane'.buildDepsOnly commonArgs;
in {
  default = crane'.buildPackage (commonArgs
    // {
      cargoArtifacts = deps;
    });
}
