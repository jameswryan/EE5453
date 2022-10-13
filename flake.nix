{
  description = "EE5453 Intro to Computer and Network Security";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils , rust-overlay, ...}:
    flake-utils.lib.eachDefaultSystem
      (system:
        let 
          overlays = [ (import rust-overlay) ];
          pkgs = import nixpkgs {
            inherit system overlays;
          };
          in 
          with pkgs; {
          devShells.default = mkShell {
            buildInputs = [
              openssl
              pkg-config
              rust-bin.beta.latest.default
              
              pandoc
              tectonic
            ];
          };
        }
      );
}