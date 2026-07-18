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
  };

  outputs = { self, nixpkgs, rust-overlay }:
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
      devShells = forAllSystems ({ pkgs, ... }:
        let
          rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust_toolchain.toml;
        in
        {
          # liblogosdelivery is no longer consumed as a prebuilt package. The
          # waku-bindings crate under vendor/ builds it from its own Nim vendor
          # submodule (`make liblogosdelivery STATIC=1`) and offers no hook for
          # a prebuilt one, so this shell supplies that build's toolchain rather
          # than the library. The vendor's `make update` bootstraps its own
          # pinned Nim compiler, so Nim itself is not listed here.
          default = pkgs.mkShell {
            nativeBuildInputs = [
              rustToolchain
              pkgs.cmake
              pkgs.git
              pkgs.gnumake
              pkgs.pkg-config
              pkgs.perl
              pkgs.protobuf
              pkgs.which
            ];
          };
        }
      );
    };
}
