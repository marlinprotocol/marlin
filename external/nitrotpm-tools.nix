{
  nixpkgs,
  systemConfig,
  naersk,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
  src = pkgs.fetchFromGitHub {
    owner = "aws";
    repo = "NitroTPM-Tools";
    rev = "ec21ed738ba628fe460e524b3c485aed9564fe0a";
    sha256 = "sha256-ZTASHHa+LQ/hNaM0qfsaGdNwkZQQZnR9+f05DHbviLw=";
  };
  naersk' = pkgs.callPackage naersk {};
in {
  default = naersk'.buildPackage {
    src = src;
    nativeBuildInputs = [
      pkgs.pkg-config
      pkgs.autoPatchelfHook
    ];
    buildInputs = [
      pkgs.tpm2-tss
      pkgs.libgcc
    ];
  };
}
