{
  lib,
  rustPlatform,
  pam,
}:

let
  cargoToml = lib.importTOML ./Cargo.toml;
in
rustPlatform.buildRustPackage {
  pname = "pam-idp";
  inherit (cargoToml.package) version;

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./Cargo.toml
      ./Cargo.lock
      ./src
      ./tests
      ./examples
    ];
  };

  cargoLock.lockFile = ./Cargo.lock;

  nativeBuildInputs = [ pam ];
  buildInputs = [ pam ];

  doCheck = true;

  postInstall = ''
    mkdir -p $out/lib/security
    mv $out/lib/libpam_idp.so $out/lib/security/pam_idp.so
    rm -f $out/lib/libpam_idp.rlib $out/lib/libpam_idp.a
  '';

  meta = {
    description = "PAM module: directory password or SSO via the OAuth 2.0 device flow";
    homepage = "https://github.com/charlie-horse/idp-pam";
    license = lib.licenses.asl20;
    platforms = lib.platforms.linux;
  };
}
