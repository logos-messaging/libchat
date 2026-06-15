{
  description = "libchat - Logos Chat cryptographic library";

  inputs = {
    # nixos-unstable-small has both crates.io UA fixes (NixOS/nixpkgs#512735,
    # NixOS/nixpkgs#524985); nixos-unstable hasn't caught up yet as of 2026-05-28.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    logos-delivery = {
      url = "github:logos-messaging/logos-delivery";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay, logos-delivery }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f {
        inherit system;
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
      });
    in
    {
      packages = forAllSystems ({ system, ... }:
        {
          logos-delivery = logos-delivery.packages.${system}.liblogosdelivery.override {
            enablePostgres = false;
            enableNimDebugDlOpen = false;
            chroniclesLogLevel = "FATAL";
          };
        }
      );

      devShells = forAllSystems ({ pkgs, ... }:
        let
          rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust_toolchain.toml;
        in
        {
          default = pkgs.mkShell {
            nativeBuildInputs = [
              rustToolchain
              pkgs.pkg-config
              pkgs.cmake
              pkgs.perl
              pkgs.protobuf
            ];
          };
        }
      );
    };
}
