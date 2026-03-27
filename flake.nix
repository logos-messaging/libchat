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

            # perl: required by openssl-sys (transitive dep)
            nativeBuildInputs = [ pkgs.perl pkgs.pkg-config pkgs.cmake ];
            doCheck = false; # tests require network access unavailable in nix sandbox

            postBuild = ''
              cargo run --frozen --release --bin generate-libchat-headers --features headers
            '';

            installPhase = ''
              runHook preInstall
              mkdir -p $out/lib $out/include

              # Copy shared library (platform-dependent extension)
              cp target/release/liblibchat.so    $out/lib/ 2>/dev/null || true
              cp target/release/liblibchat.dylib $out/lib/ 2>/dev/null || true
              cp target/release/liblibchat.a     $out/lib/ 2>/dev/null || true

              # Fail if no library was produced
              if [ -z "$(ls $out/lib/liblibchat.* 2>/dev/null)" ]; then
                echo "ERROR: No library artifact found in target/release/"
                exit 1
              fi

              # Copy generated header
              cp libchat.h $out/include/

              runHook postInstall
            '';

            meta = with pkgs.lib; {
              description = "Logos Chat cryptographic library (C FFI)";
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
