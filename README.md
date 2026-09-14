# vela

vela is a post-link obfuscator for WebAssembly. It rewrites a compiled `.wasm`
module, so you can add it after linking without changing your compiler or source
code.

By default, it encrypts data segments, turns selected direct calls into table
dispatches, and replaces data addresses and generated dispatch indices with arithmetic
over mutable globals. Control flow flattening and opaque predicates are
optional.

## Usage

Build from the checkout with Cargo.

```sh
cargo build --release --locked
./target/release/vela run app.wasm -o app.obf.wasm --seed 1 --check
```

> [!IMPORTANT]
> Run vela after `wasm-opt`. Optimizing the rewritten module can simplify the
> arithmetic vela added.

Install the `vela` command with `cargo install vela-wasm --locked`, or from
the checkout with `cargo install --path . --locked`. The examples below
assume `vela` is on your `PATH`.

With Nix, `nix develop` provides nightly Rust, Clippy, rust-analyzer and the Wasm
tools. On x86_64 and AArch64 Linux, the Wild linker is used.

```sh
vela run app.wasm -o app.obf.wasm --seed 1 --flatten --opaque --check
vela check app.wasm app.obf.wasm
```

Use `--function` to select input functions by exact name or export name. For a
stripped module, use an input function index such as `--function '#12'`. Repeat
the option to select several functions. Unmatched selectors fail the rewrite.
`--report-functions` prints those indices, instruction counts before and after
rewriting, pass counts, and reasons flattening refused a sequence.
Indices refer to that input file and can change when it is rebuilt.

`--call-function`, `--marker-function`, `--flatten-function` and
`--opaque-function` each override `--function` for one pass. They are repeatable
and do not enable a disabled pass. For example, this keeps flattening on `init`
and `encode` while rewriting constants only in `process`.

```sh
vela run app.wasm -o app.obf.wasm --flatten \
  --function init --function encode --marker-function process --report-functions
```

The library exposes the same overrides through `Config.pass_functions`, keyed
by `CodePass`. An absent entry inherits `Config.functions`, and an empty list
in a present entry selects every input function for that pass.

`--include-callees` expands each pass's selection through direct calls, including
tail calls. Repeat `--exclude-reachable` to keep a function and all of its
callees out of every code pass, including explicit pass overrides. This can
cover initialization helpers while excluding helpers shared with a hot path.

```sh
vela run app.wasm -o app.obf.wasm --flatten --function init \
  --include-callees --exclude-reachable process --report-functions
```

The library uses `Config.include_callees` and `Config.exclude_reachable` for
these options. Graph traversal rejects reachable imports and dynamic calls
because their targets or host callbacks cannot be proven from direct calls.
Explicit function selection without graph traversal remains available.

Selection applies to the code passes on input functions. Data encryption still
applies across the module and can insert decryption gates in excluded functions.
Generated runtime helpers are excluded from the code passes.

`--check` compares the modules before writing the output. `vela check` runs the
same comparison on two existing files.

vela accepts modules with at most one 32-bit memory. Modules with multiple
memories or a 64-bit memory are rejected before rewriting.

| Option                           | Default     | Notes                                                        |
| -------------------------------- | ----------- | ------------------------------------------------------------ |
| `--seed <u64>`                   | 0           | Deterministic rewrite seed.                                  |
| `--function <selector>`          | All         | Exact name, export or `#index`, repeatable.                  |
| `--include-callees`              | Off         | Expand each pass's roots through direct calls.               |
| `--exclude-reachable <selector>` | None        | Exclude roots and their callees from every code pass.        |
| `--call-function <selector>`     | Inherited   | Override direct-call selection.                              |
| `--marker-function <selector>`   | Inherited   | Override constant selection.                                 |
| `--flatten-function <selector>`  | Inherited   | Override flattening selection.                               |
| `--opaque-function <selector>`   | Inherited   | Override opaque selection.                                   |
| `--report-functions`             | Off         | Per-function counts and flatten refusals.                    |
| `--check`                        | Off         | Compare before writing.                                      |
| `--fuel <u64>`                   | 100 million | Per-module verification fuel, also accepted by `vela check`. |
| `--timeout <seconds>`            | 30          | Deadline for the entire verification worker.                 |
| `--process-memory <bytes>`       | 1 GiB       | Worker virtual address-space limit.                          |
| `--eager`                        | Off         | Decrypt all segments at startup.                             |
| `--markers-all`                  | Off         | Rewrite all `i32` constants.                                 |
| `--marker-depth <n>`             | 2           | Marker depth between 0 and 64.                               |
| `--pool-size <n>`                | 8           | Pool globals, minimum 2.                                     |
| `--indirect-ratio <pct>`         | 60%         | Call rewrite chance, 0-100%.                                 |
| `--flatten`                      | Off         | Flatten control flow.                                        |
| `--flatten-ratio <pct>`          | 70%         | 0-100%, needs `--flatten`.                                   |
| `--max-regions <n>`              | 6           | Minimum 2, needs `--flatten`.                                |
| `--opaque`                       | Off         | Insert never-taken branches.                                 |
| `--opaque-ratio <pct>`           | 20%         | 0-100%, needs `--opaque`.                                    |
| `--no-data-enc`                  | Off         | Disable data encryption.                                     |
| `--no-markers`                   | Off         | Disable marker arithmetic.                                   |
| `--no-indirect`                  | Off         | Keep direct calls.                                           |
| `--debug-names`                  | Off         | Name generated functions.                                    |

## What it does

### Data encryption

Data encryption rewrites supported active segments and adds a runtime decryptor.
With lazy staging, vela puts a decryption gate at the entry of each function
whose resolved memory access or pointer argument reaches a segment. The analysis
carries constants through locals and wrapping `i32` arithmetic within each
instruction sequence. It includes load and store offsets, access widths, and
bulk-memory ranges, so an access crossing two segments gates both. The first
call decrypts the segment in place, whereas later calls skip the decryption.

An unresolved memory address, length, imported call, indirect call or unsupported
instruction forces all encrypted segments to decrypt during startup. Values
crossing structured control flow lose their known state, so loops and branches
can also force eager decryption. Vela does not yet propagate values between
functions or merge branch states.

A segment also stays eager if its address depends on a base global, if any
four-byte window in data points into it, or if no function has a resolved
reference to it. `--eager` decrypts all encrypted segments during startup,
before the module's original start function runs. Encryption rejects active
segments whose placements cannot be proven disjoint, since separately decrypting
shared bytes would corrupt the initialized data.

Staging delays decryption. It doesn't erase plaintext afterward, so running
enough functions can leave every segment decrypted. A module with one large data
segment gets little benefit from staging, and a loader's relocation function can
force that segment to decrypt as soon as it runs. Note that passive segments and
offset expressions it can't reconstruct are left alone.

### Calls and constants

Indirect calls replace a `call` instruction's explicit target with a function
table index. For relocatable modules, vela extends an existing element segment,
forms indices relative to its base global, and grows the `dylink.0` table
reservation. If an imported table has no usable segment to extend, the pass
skips it.

Marker arithmetic replaces selected `i32.const` instructions with expressions
over mutable globals. Those globals get mixed during startup, before decryption
or the module's original start function runs, so reading their initialisers from
the binary gives you the wrong values. vela checks each expression before
emitting it and leaves the original constant alone if the result doesn't match.

vela records the dispatch constants it generates, so the marker pass can find
them even after flattening moves their instructions. The
[address analysis](src/references.rs) also records original constants that
contribute to resolved data addresses, including arithmetic operands outside the
data segment. A coincidental integer inside a data segment is no longer enough
to select a constant.

### Control flow

Flattening cuts a sequence where the operand stack is empty, shuffles the
regions, and runs them through a `br_table` dispatch loop. It runs before marker
arithmetic, which rewrites the generated dispatch state constants without needing
`--markers-all`.
Nested loops retain their structure and can be flattened separately. Sequences
with unsupported stack effects or no legal cuts are left alone.

The stack analysis lives in [src/stack.rs](src/stack.rs). walrus stores branch
targets as `InstrSeqId` references, so wrapping a region in new blocks doesn't
require renumbering branch depths. Because those targets survive the rewrite,
vela can flatten individual sequences _without_ rebuilding the whole function's
control flow.

Opaque predicates add never-taken branches at eligible sequence entries. They're
off by default because they add size for relatively little benefit.

## Correctness

A module can validate and still return the wrong result. `--check` instantiates
both versions with wasmi and calls each zero-argument function export in name
order. It compares typed results and trap kinds, then a digest of reachable
linear memory after those calls.

The checker supplies stub imports. It doesn't run the module in your
application's host, and it doesn't call exports that take arguments. Export
mismatches fail the check, including added or removed zero-argument exports.
Failed instantiation, no callable exports, and non-null reference results also
fail the check. Memory differences are advisory because lazy staging can leave
unused segments encrypted.

The library provides `worker::Verifier::compare_scenario` for exports with arguments
and state shared across calls. A scenario is an ordered list of typed calls,
writes to exported memory, and reads of specific memory ranges. Both modules
execute the whole list on one instance each. Requested memory reads compare
exact bytes and are fatal differences, while the final whole-memory digest
remains advisory. The caller checks the returned comparisons with `agrees` and
`is_advisory`, just as the CLI does.

`verify::HostConfig` sets separate memory and table bases, both defaulting to 64.
The stub host preserves imported global mutability and initializes unrelated
globals to their type's zero value. Imported functions still return zero values,
so applications with host callbacks need verification in their own host too.

Verification gives each module a finite budget shared across initialization and
all subsequent calls. Defaults are 100 million fuel units, 64 MiB of linear
memory, one million table elements, and 16 MiB of captured memory reads. The
memory and table budgets cover aggregate allocations within an instance, and
read captures accumulate across the scenario. Configure `HostConfig.limits` for
a different workload.

Both methods on `worker::Verifier` accept a `verify::HostConfig`.
The CLI accepts `--fuel` on `run --check` and `check` for modules whose
initialization or exported workload needs more than the default fuel budget.

Verification runs in a fresh process with a 30-second deadline and a 1 GiB
virtual address-space cap. The cap is installed before the request is decoded,
so it covers Wasm parsing, compilation and execution. Requests and replies are
limited to 64 MiB each. Timeouts, crashes, oversized replies and malformed
replies fail verification, and the parent kills and reaps the worker before
returning. A valid reply followed by a failing exit is still a failure.

Workers clear `LD_PRELOAD` and `LD_AUDIT` before exec because injected allocators
can reserve terabytes before the address-space cap is installed.

Process isolation currently requires Linux. Other platforms return an explicit
unsupported-platform error. The limits apply to the verification worker, while
the caller's input buffers and Vela's rewriting passes remain in the parent.
Use `worker::Limits` to configure the process bounds, or `--timeout` and
`--process-memory` from the CLI.

Library hosts call `worker::entrypoint()` at the start of `main` and return
immediately when it returns `true`. The same executable can then serve as the
worker, without installing a separate Vela binary.

```rust
if worker::entrypoint()? {
   return Ok(());
}
let verifier = worker::Verifier::new(
   &std::env::current_exe()?,
   worker::Limits::default(),
)?;
let comparisons = verifier.compare(&before, &after, verify::HostConfig::default())?;
```

Budget exhaustion returns `worker::VerificationError::LimitExceeded`, even when both modules
would exhaust the same budget. Ordinary guest traps remain comparable. A
`memory.grow` or `table.grow` refused by the module's declared maximum still
returns its normal failure value.

> [!WARNING]
> Matching trap kinds count as agreement, so a passing check can still mean
> both calls trapped.

Every rewrite also performs a [placement audit](src/audit.rs), even without
`--check`. The library rejects active data or element segments at absolute `i32`
offsets into imported memories or tables. Running a module alone won't
necessarily catch those mistakes, because it can read back the same slots it
wrote. Under a dynamic loader, those slots may belong to another module. The
audit checks that placement rule, but doesn't verify the loader's full
reservation or relocation behavior.

The bundled [sample fixture](fixtures/sample.wat) exercises data references, a
stored pointer and table calls. You can reproduce this report with its
checked-in `.wasm` file.

```sh
vela run fixtures/sample.wasm -o sample.obf.wasm --seed 1 --check
```

```
check     1 exports and linear memory agree
data      4/4 segments encrypted, 91 bytes
staging   0 lazy, 4 forced eager, 3 unresolved memory uses
markers   10 constants rewritten (4 dispatch) over a pool of 8, 0 left alone
calls     4 direct calls promoted to indirect
opaque    0 bogus branches inserted
flatten   0 sequences into 0 dispatch regions, 0 not safely splittable
size      379 -> 912 bytes (+140.6%)
```

The fixture is only 379 bytes, so the added runtime accounts for much of its
size increase. Measure overhead on your own module, especially with flattening
or `--markers-all` enabled.

[fixtures/reloc.wat](fixtures/reloc.wat) uses offsets relative to an imported
`__memory_base`. Its binary and rewritten output need
`wasm-validate --enable-extended-const` when validating with WABT.

## Limits

vela adds work for static analysis; it explicitly does not provide a protection
boundary. The module ships its decryption code and seeds, and decrypted data
remains in linear memory. Anyone who can run the module can recover that data.
Executable code isn't encrypted, and vela doesn't add an integrity check.
