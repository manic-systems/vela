{
  mkShell,
  toolchain,
  rust-analyzer,
  binaryen,
  wabt,
  nixfmt,
  linkerInputs,
}:
mkShell {
  name = "vela";
  strictDeps = true;
  packages = [
    toolchain
    rust-analyzer
    binaryen
    wabt
    nixfmt
  ]
  ++ linkerInputs;
  env.RUST_SRC_PATH = "${toolchain}/lib/rustlib/src/rust/library";
}
