{
  lib,
  rustPlatform,
  linkerInputs,
  systems,
}:
let
  manifest = (lib.importTOML ../Cargo.toml).package;
in
rustPlatform.buildRustPackage {
  pname = "vela";
  inherit (manifest) version;

  src = ../.;
  cargoLock.lockFile = ../Cargo.lock;

  strictDeps = true;
  nativeBuildInputs = linkerInputs;

  meta = {
    inherit (manifest) description;
    homepage = manifest.repository;
    license = lib.licenses.eupl12;
    maintainers = [ lib.maintainers.amaanq ];
    mainProgram = "vela";
    platforms = systems;
  };
}
