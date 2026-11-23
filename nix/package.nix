{
  lib,
  stdenv,
  buildPackages,
  installShellFiles,
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
  nativeBuildInputs = [ installShellFiles ] ++ linkerInputs;

  env = lib.optionalAttrs (linkerInputs != [ ]) {
    RUSTFLAGS = "-Clinker=${buildPackages.clang}/bin/${buildPackages.clang.targetPrefix}clang -Clink-arg=--ld-path=wild";
  };

  postInstall = lib.optionalString (stdenv.hostPlatform.emulatorAvailable buildPackages) (
    let
      vela = "${stdenv.hostPlatform.emulator buildPackages} $out/bin/vela";
    in
    ''
      installShellCompletion --cmd vela \
        --bash    <(COMPLETE=bash ${vela}) \
        --zsh     <(COMPLETE=zsh  ${vela}) \
        --fish    <(COMPLETE=fish ${vela}) \
        --nushell <(COMPLETE=nu   ${vela})
    ''
  );

  meta = {
    inherit (manifest) description;
    homepage = manifest.repository;
    license = lib.licenses.eupl12;
    maintainers = [ lib.maintainers.amaanq ];
    mainProgram = "vela";
    platforms = systems;
  };
}
