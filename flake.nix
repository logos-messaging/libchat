{
  description = "libchat - Logos Chat cryptographic library";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f {
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
      });
    in
    {
      packages = forAllSystems ({ pkgs }:
        let
          rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust_toolchain.toml;
          rustPlatform = pkgs.makeRustPlatform {
            cargo = rustToolchain;
            rustc = rustToolchain;
          };
        in
        {
          default = rustPlatform.buildRustPackage {
            pname = "libchat";
            version = "0.1.0";
            src = pkgs.lib.cleanSourceWith {
              src = ./.;
              filter = path: type:
                let base = builtins.baseNameOf path;
                in !(builtins.elem base [ "target" "nim-bindings" ".git" ".github" "tmp" ]);
            };

            cargoLock = {
              lockFile = ./Cargo.lock;
              outputHashes = {
                "chat-proto-0.1.0" = "sha256-aCl80VOIkd/GK3gnmRuFoSAvPBfeE/FKCaNlLt5AbUU=";
              };
            };

            nativeBuildInputs = [ pkgs.perl pkgs.pkg-config pkgs.cmake ];
            buildType = "release";
            # Override panic=abort from workspace Cargo.toml — incompatible with buildRustPackage
            CARGO_PROFILE_RELEASE_PANIC = "unwind";
            # Tests run in CI; some require network access unavailable in the Nix sandbox
            doCheck = false;

            postBuild = ''
              cargo run --frozen --release --bin generate-headers --features headers -p client-ffi -- crates/client-ffi/client_ffi.h
            '';

            installPhase = ''
              runHook preInstall
              mkdir -p $out/lib $out/include
              cp target/${pkgs.stdenv.hostPlatform.rust.rustcTarget}/release/libclient_ffi.a $out/lib/
              cp crates/client-ffi/client_ffi.h $out/include/
              runHook postInstall
            '';

            meta = with pkgs.lib; {
              description = "Logos Chat library (C FFI)";
              platforms = platforms.unix;
            };
          };
        }
      );

      devShells = forAllSystems ({ pkgs }:
        let
          rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust_toolchain.toml;
        in
        {
          default = pkgs.mkShell {
            nativeBuildInputs = [
              rustToolchain
              pkgs.pkg-config
              pkgs.cmake
            ];
          };
        }
      );
    };
}
