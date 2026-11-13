{
  description = "pam_idp: PAM module with a password/SSO menu and the OAuth 2.0 device flow";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      overlays.default = final: _prev: {
        pam-idp = final.callPackage ./package.nix { };
      };

      packages = forAllSystems (pkgs: rec {
        pam-idp = pkgs.callPackage ./package.nix { };
        default = pam-idp;
      });

      checks = forAllSystems (
        pkgs:
        let
          pkg = self.packages.${pkgs.stdenv.hostPlatform.system}.pam-idp;
        in
        {
          build = pkg;

          clippy = pkg.overrideAttrs (old: {
            pname = "pam-idp-clippy";
            nativeBuildInputs = old.nativeBuildInputs ++ [ pkgs.clippy ];
            buildPhase = ''
              runHook preBuild
              cargo clippy --offline --all-targets -- -D warnings
              runHook postBuild
            '';
            doCheck = false;
            installPhase = ''
              touch $out
            '';
            postInstall = "";
          });

          fmt =
            pkgs.runCommand "pam-idp-fmt"
              {
                nativeBuildInputs = [
                  pkgs.cargo
                  pkgs.rustfmt
                ];
              }
              ''
                cd ${pkg.src}
                cargo fmt --check
                touch $out
              '';
        }
      );

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            clippy
            rustfmt
            rust-analyzer
            pam
            pamtester
            cargo-deny
            cargo-llvm-cov
          ];
          # cargo-llvm-cov needs llvm-cov and llvm-profdata from the LLVM that
          # rustc was built with; nixpkgs' rustc has no llvm-tools-preview.
          LLVM_COV = "${pkgs.rustc.llvmPackages.llvm}/bin/llvm-cov";
          LLVM_PROFDATA = "${pkgs.rustc.llvmPackages.llvm}/bin/llvm-profdata";
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
