use std::{
   collections::BTreeMap,
   env,
   fs,
   path::{
      Path,
      PathBuf,
   },
   time::Duration,
};

use eyre::{
   Result,
   WrapErr as _,
   bail,
};
use pound::Parse;
use vela::{
   config::{
      CodePass,
      Config,
      FunctionSelector,
      MarkerDepth,
      Percentage,
      PoolSize,
   },
   verify,
   worker,
};

#[derive(Parse)]
#[pound(name = "vela")]
/// A post-link obfuscator for WebAssembly.
enum Command {
   /// Rewrite a module and write the result.
   Run {
      /// Rewrite only these input function names, exports or #indices,
      /// repeatable.
      #[pound(long, parse = "str::parse")]
      function: Vec<FunctionSelector>,

      /// Rewrite only these functions in the indirect call pass. Scope only,
      /// an absent flag inherits --function and an empty selection inherits it
      /// too. Never enables a globally disabled pass. Repeatable.
      #[pound(long, parse = "str::parse")]
      call_function: Vec<FunctionSelector>,

      /// Rewrite only these functions in the marker pass. Scope only, an
      /// absent flag inherits --function and an empty selection inherits it
      /// too. Never enables a globally disabled pass. Repeatable.
      #[pound(long, parse = "str::parse")]
      marker_function: Vec<FunctionSelector>,

      /// Rewrite only these functions in the flatten pass. Scope only, an
      /// absent flag inherits --function and an empty selection inherits it
      /// too. Never enables a globally disabled pass. Repeatable.
      #[pound(long, parse = "str::parse")]
      flatten_function: Vec<FunctionSelector>,

      /// Rewrite only these functions in the opaque pass. Scope only, an
      /// absent flag inherits --function and an empty selection inherits it
      /// too. Never enables a globally disabled pass. Repeatable.
      #[pound(long, parse = "str::parse")]
      opaque_function: Vec<FunctionSelector>,

      /// Expand each code-pass root set through direct calls.
      #[pound(long)]
      include_callees: bool,

      /// Keep these functions and their reachable callees out of every code
      /// pass, including overrides. Repeatable.
      #[pound(long, parse = "str::parse")]
      exclude_reachable: Vec<FunctionSelector>,

      /// Print instruction counts and rewrite results for each input function.
      #[pound(long)]
      report_functions: bool,
      /// Module to rewrite.
      input:            PathBuf,

      #[pound(short, long)]
      /// Where the rewritten module gets written.
      output: PathBuf,

      /// Fixing the seed makes the whole transformation reproducible.
      #[pound(long, default = "0")]
      seed: u64,

      /// Skip data segment encryption entirely.
      #[pound(long)]
      no_data_enc: bool,

      /// Fold ciphertext and integer global initializers into marker state.
      #[pound(long)]
      integrity: bool,

      /// Decrypt every segment up front instead of on first use.
      #[pound(long)]
      eager: bool,

      /// Skip marker arithmetic entirely.
      #[pound(long)]
      no_markers: bool,

      /// Advance encoded pool state without changing marker results.
      #[pound(long)]
      evolve_pool: bool,

      /// Recursion depth of each synthesised marker expression.
      #[pound(long, default = "2", parse = "str::parse")]
      marker_depth: MarkerDepth,

      /// Number of globals the marker expressions draw from.
      #[pound(long, default = "8", parse = "str::parse")]
      pool_size: PoolSize,

      /// Rewrite all i32 constants, including non-address operands.
      #[pound(long)]
      markers_all: bool,

      /// Skip promoting direct calls to indirect ones.
      #[pound(long)]
      no_indirect: bool,

      /// Percentage of direct calls promoted to table dispatches.
      #[pound(long, default = "60", parse = "str::parse")]
      indirect_ratio: Percentage,

      /// Insert never-taken branches. Off by default because it costs size for
      /// the least benefit.
      #[pound(long)]
      opaque: bool,

      /// Percentage of eligible branches turned opaque.
      #[pound(long, default = "20", parse = "str::parse")]
      opaque_ratio: Percentage,

      /// Rewrite instruction sequences as `br_table` dispatch loops.
      #[pound(long)]
      flatten: bool,

      /// Percentage of eligible sequences flattened.
      #[pound(long, default = "70", parse = "str::parse")]
      flatten_ratio: Percentage,

      /// Upper bound on regions a single sequence is cut into.
      #[pound(long, default = "6")]
      max_regions: usize,

      /// Compare zero-argument exports before writing the output.
      #[pound(long)]
      check: bool,

      /// Fuel budget per module when checking, defaults to 100 million.
      #[pound(long)]
      fuel: Option<u64>,

      /// Deadline in seconds for the complete verification worker.
      #[pound(long)]
      timeout: Option<u64>,

      /// Maximum virtual address space in bytes for the verification worker.
      #[pound(long)]
      process_memory: Option<u64>,

      /// Name generated helpers for debugging, exposing them to readers.
      #[pound(long)]
      debug_names: bool,
   },
   /// Run every zero-argument export of two modules and compare the results.
   Check {
      /// Path to the original, unrewritten module.
      before:         PathBuf,
      /// Path to the module produced by a previous `run`.
      after:          PathBuf,
      /// Fuel budget per module, defaults to 100 million.
      #[pound(long)]
      fuel:           Option<u64>,
      /// Deadline in seconds for the complete verification worker.
      #[pound(long)]
      timeout:        Option<u64>,
      /// Maximum virtual address space in bytes for the verification worker.
      #[pound(long)]
      process_memory: Option<u64>,
   },
}

fn main() -> Result<()> {
   if worker::entrypoint()? {
      return Ok(());
   }
   color_eyre::install()?;

   match Command::parse() {
      Command::Run {
         function,
         call_function,
         marker_function,
         flatten_function,
         opaque_function,
         include_callees,
         exclude_reachable,
         report_functions,
         input,
         output,
         seed,
         no_data_enc,
         integrity,
         eager,
         no_markers,
         evolve_pool,
         marker_depth,
         pool_size,
         markers_all,
         no_indirect,
         indirect_ratio,
         opaque,
         opaque_ratio,
         flatten,
         flatten_ratio,
         max_regions,
         check,
         fuel,
         timeout,
         process_memory,
         debug_names,
      } => {
         let pass_functions = [
            (CodePass::Indirect, call_function),
            (CodePass::Markers, marker_function),
            (CodePass::Flatten, flatten_function),
            (CodePass::Opaque, opaque_function),
         ]
         .into_iter()
         .filter(|entry| !entry.1.is_empty())
         .collect::<BTreeMap<_, _>>();

         let config = Config {
            functions: function,
            pass_functions,
            include_callees,
            exclude_reachable,
            seed,
            data_enc: !no_data_enc,
            integrity,
            lazy: !eager,
            markers: !no_markers,
            evolve_pool,
            marker_depth,
            pool_size,
            markers_all,
            indirect_calls: !no_indirect,
            indirect_ratio,
            opaque,
            opaque_ratio,
            flatten,
            flatten_ratio,
            max_regions,
            debug_names,
         };

         run(
            &input,
            &output,
            &config,
            check,
            report_functions,
            fuel,
            process_limits(timeout, process_memory),
         )
      },
      Command::Check {
         before: before_path,
         after: after_path,
         fuel,
         timeout,
         process_memory,
      } => {
         let before = fs::read(&before_path).wrap_err("reading the original module")?;
         let after = fs::read(&after_path).wrap_err("reading the rewritten module")?;
         report_comparison(
            &before,
            &after,
            fuel,
            process_limits(timeout, process_memory),
         )
      },
   }
}

/// Absent CLI overrides preserve the library's process limits.
fn process_limits(timeout: Option<u64>, memory: Option<u64>) -> worker::Limits {
   let mut limits = worker::Limits::default();
   if let Some(seconds) = timeout {
      limits.timeout = Duration::from_secs(seconds);
   }
   if let Some(bytes) = memory {
      limits.address_space_bytes = bytes;
   }
   limits
}

/// Applies the configured passes to `input_path` and writes the result to
/// `output_path`.
#[expect(clippy::print_stdout, reason = "this is the CLI's reporting output")]
fn run(
   input_path: &Path,
   output_path: &Path,
   config: &Config,
   check: bool,
   report_functions: bool,
   fuel: Option<u64>,
   limits: worker::Limits,
) -> Result<()> {
   let input =
      fs::read(input_path).wrap_err_with(|| format!("reading {}", input_path.display()))?;

   let (output, report) = vela::transform(&input, config)?;

   if check {
      report_comparison(&input, &output, fuel, limits)?;
   }

   fs::write(output_path, &output)
      .wrap_err_with(|| format!("writing {}", output_path.display()))?;

   println!("{report}");
   if report_functions {
      for function in &report.functions {
         println!("{function}");
      }

      for unresolved in &report.unresolved {
         println!("{unresolved}");
      }

      for segment in &report.segments {
         println!("{segment}");
      }
   }
   let before_len = u32::try_from(input.len()).map_or(f64::NAN, f64::from);
   let after_len = u32::try_from(output.len()).map_or(f64::NAN, f64::from);

   let delta = (after_len / before_len - 1.0_f64) * 100.0_f64;
   println!(
      "size      {} -> {} bytes ({delta:+.1}%)",
      input.len(),
      output.len()
   );

   Ok(())
}

/// Runs both modules and prints what differs, failing on any fatal difference.
#[expect(clippy::print_stdout, reason = "this is the CLI's reporting output")]
#[expect(clippy::print_stderr, reason = "this is the CLI's reporting output")]
fn report_comparison(
   before: &[u8],
   after: &[u8],
   fuel: Option<u64>,
   limits: worker::Limits,
) -> Result<()> {
   let mut host = verify::HostConfig::default();
   if let Some(budget) = fuel {
      host.limits.fuel = budget;
   }
   let verifier = worker::Verifier::new(&env::current_exe()?, limits)?;
   let comparisons = verifier.compare(before, after, host)?;

   let (fatal, advisory): (Vec<_>, Vec<_>) = comparisons
      .iter()
      .filter(|entry| !entry.agrees())
      .partition(|entry| !entry.is_advisory());

   for entry in fatal.iter().chain(&advisory) {
      eprintln!("{entry}");
   }

   if !fatal.is_empty() {
      bail!(
         "{} of {} observables changed",
         fatal.len(),
         comparisons.len()
      );
   }

   let exports = comparisons
      .iter()
      .filter(|entry| !entry.is_advisory())
      .count();

   if advisory.is_empty() {
      println!("check     {exports} exports and linear memory agree");
   } else {
      println!("check     {exports} exports agree, memory differs (expected under lazy staging)");
   }

   Ok(())
}
