{
  nixpkgs,
  systemConfig,
  naersk,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
  naersk' = pkgs.callPackage naersk {};
in {
  default = naersk'.buildPackage {
    src = ./.;
  };
}
