{
  description = "A post-link obfuscator for WebAssembly modules";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs?ref=nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { nixpkgs, fenix, ... }:
    let
      inherit (nixpkgs) lib;
      systems = lib.intersectLists (builtins.attrNames fenix.packages) (
        lib.systems.doubles.linux ++ lib.systems.doubles.darwin
      );
      perSystem = lib.genAttrs systems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system} or (import nixpkgs { inherit system; });
          toolchain = fenix.packages.${system}.complete.withComponents [
            "cargo"
            "clippy"
            "rust-src"
            "rustc"
            "rustfmt"
          ];
          rustPlatform = pkgs.makeRustPlatform {
            cargo = toolchain;
            rustc = toolchain;
          };
          inherit (pkgs.stdenv) hostPlatform;
          hasWild = hostPlatform.isLinux && (hostPlatform.isx86_64 || hostPlatform.isAarch64);
          linkerInputs = lib.optionals hasWild [
            pkgs.clang
            pkgs.wild
          ];
        in
        {
          package = pkgs.callPackage ./nix/package.nix {
            inherit rustPlatform linkerInputs systems;
          };

          shell = pkgs.callPackage ./nix/shell.nix {
            inherit toolchain linkerInputs;
            rust-analyzer = fenix.packages.${system}.rust-analyzer;
          };

          formatter = pkgs.nixfmt;
        }
      );
    in
    {
      packages = lib.mapAttrs (_: config: {
        vela = config.package;
        default = config.package;
      }) perSystem;
      devShells = lib.mapAttrs (_: config: { default = config.shell; }) perSystem;
      checks = lib.mapAttrs (_: config: { vela = config.package; }) perSystem;
      formatter = lib.mapAttrs (_: config: config.formatter) perSystem;
    };
}
