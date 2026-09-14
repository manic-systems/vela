use std::{
   env,
   io,
   path::{
      Path,
      PathBuf,
   },
   process::ExitStatus,
   time::{
      Duration,
      Instant,
   },
};

use thiserror::Error;

use crate::{
   verify::{
      Action,
      Comparison,
      HostConfig,
      ModuleSide,
      Resource,
   },
   verify_wire::Request,
};
#[cfg(target_os = "linux")]
use crate::{
   verify_wire::{
      self,
      Response,
   },
   worker_process,
};

#[derive(Debug, Clone, Copy)]
pub struct Limits {
   /// One deadline covers communication, parsing, compilation and execution.
   pub timeout:             Duration,
   /// Linux limits the worker's entire virtual address space to this size.
   pub address_space_bytes: u64,
   /// Requests and replies each have this serialized byte limit.
   pub message_bytes:       usize,
}

impl Default for Limits {
   #[inline]
   fn default() -> Self {
      Self {
         timeout:             Duration::from_secs(30),
         address_space_bytes: 1024 * 1024 * 1024,
         message_bytes:       64 * 1024 * 1024,
      }
   }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VerificationError {
   #[error("isolated verification requires Linux")]
   UnsupportedPlatform,
   #[error("verification process limits must be positive and representable")]
   InvalidLimits,
   #[error("verification worker exceeded its deadline")]
   Timeout,
   #[error("verification message exceeds {limit} bytes")]
   MessageTooLarge { limit: usize },
   #[error("verification worker exited with {0}")]
   Exited(ExitStatus),
   #[error("verification worker returned an invalid or trailing reply")]
   InvalidReply,
   #[error("communicating with the verification worker")]
   Io {
      #[source]
      source: io::Error,
   },
   #[error("encoding or decoding the verification message")]
   Codec {
      #[source]
      source: postcard::Error,
   },
   #[error("{side} module exceeded its verification budget for {resource}")]
   LimitExceeded {
      side:     ModuleSide,
      resource: Resource,
   },
   #[error("{message}")]
   Verification { message: String },
}

#[derive(Debug)]
pub struct Verifier {
   /// The executable must dispatch the worker entry point before normal work.
   executable: PathBuf,
   /// Process bounds are independent of Wasm fuel and guest allocation limits.
   limits:     Limits,
}

impl Verifier {
   /// Uses an executable that calls [`entrypoint`] at the start of its main
   /// function.
   ///
   /// # Errors
   ///
   /// Rejects invalid limits or an executable path that cannot be resolved.
   #[inline]
   pub fn new(executable: &Path, limits: Limits) -> Result<Self, VerificationError> {
      if limits.timeout.is_zero()
         || Instant::now().checked_add(limits.timeout).is_none()
         || matches!(limits.address_space_bytes, 0 | u64::MAX)
         || limits.message_bytes == 0
      {
         return Err(VerificationError::InvalidLimits);
      }
      let resolved = executable
         .canonicalize()
         .map_err(|source| VerificationError::Io { source })?;
      Ok(Self {
         executable: resolved,
         limits,
      })
   }

   /// Compares zero-argument exports in a fresh bounded process.
   ///
   /// # Errors
   ///
   /// Fails when verification, process limits, communication or the worker
   /// fails.
   #[inline]
   pub fn compare(
      &self,
      before: &[u8],
      after: &[u8],
      host: HostConfig,
   ) -> Result<Vec<Comparison>, VerificationError> {
      self.execute(&Request {
         before,
         after,
         actions: None,
         host,
      })
   }

   /// Runs the complete ordered scenario inside one bounded worker process.
   ///
   /// # Errors
   ///
   /// Fails when verification, process limits, communication or the worker
   /// fails.
   #[inline]
   pub fn compare_scenario(
      &self,
      before: &[u8],
      after: &[u8],
      actions: &[Action],
      host: HostConfig,
   ) -> Result<Vec<Comparison>, VerificationError> {
      self.execute(&Request {
         before,
         after,
         actions: Some(actions),
         host,
      })
   }

   /// A reply is accepted only after the worker has exited successfully.
   #[cfg(target_os = "linux")]
   fn execute(
      &self,
      request: &Request<&[u8], &[Action]>,
   ) -> Result<Vec<Comparison>, VerificationError> {
      let deadline = Instant::now()
         .checked_add(self.limits.timeout)
         .ok_or(VerificationError::InvalidLimits)?;
      let message = verify_wire::encode(request, self.limits.message_bytes)?;
      let response = worker_process::run(&self.executable, self.limits, &message, deadline)?;
      let comparisons = Vec::try_from(verify_wire::decode::<Response>(&response)?)?;
      if comparisons.len() < 2 {
         return Err(VerificationError::InvalidReply);
      }
      let mut observed = comparisons.iter();
      if let Some(actions) = request.actions {
         for action in actions {
            let matches = match *action {
               Action::WriteMemory { .. } => continue,
               Action::Call { ref name, .. } => {
                  matches!(observed.next(), Some(Comparison::Export { name: actual, .. }) if actual == name)
               },
               Action::ReadMemory {
                  ref name,
                  offset,
                  len,
               } => {
                  matches!(observed.next(), Some(Comparison::Bytes { name: actual, offset: at, before, after }) if actual == name && *at == offset && before.len() == len && after.len() == len)
               },
            };
            if !matches {
               return Err(VerificationError::InvalidReply);
            }
         }
      } else {
         let mut previous = None;
         for comparison in comparisons.iter().take(comparisons.len().saturating_sub(1)) {
            let Comparison::Export { ref name, .. } = *comparison else {
               return Err(VerificationError::InvalidReply);
            };
            if previous.is_some_and(|seen| seen >= name) {
               return Err(VerificationError::InvalidReply);
            }
            previous = Some(name);
            observed.next();
         }
         if previous.is_none() {
            return Err(VerificationError::InvalidReply);
         }
      }
      if !matches!(observed.next(), Some(Comparison::Memory { .. })) || observed.next().is_some() {
         return Err(VerificationError::InvalidReply);
      }
      if Instant::now() >= deadline {
         return Err(VerificationError::Timeout);
      }
      Ok(comparisons)
   }

   /// Unsupported hosts cannot fall back to verification in the caller's
   /// process.
   #[cfg(not(target_os = "linux"))]
   fn execute(
      &self,
      _request: &Request<&[u8], &[Action]>,
   ) -> Result<Vec<Comparison>, VerificationError> {
      Err(VerificationError::UnsupportedPlatform)
   }
}

/// Dispatches the internal worker mode before application arguments or startup
/// work.
///
/// # Errors
///
/// Fails if worker arguments, operating-system limits or the request are
/// invalid.
#[inline]
pub fn entrypoint() -> Result<bool, VerificationError> {
   let mut arguments = env::args_os().skip(1);
   if arguments
      .next()
      .is_none_or(|argument| argument != "--vela-verify-worker")
   {
      return Ok(false);
   }
   #[cfg(target_os = "linux")]
   {
      let address_space = arguments
         .next()
         .and_then(|argument| argument.to_str()?.parse().ok())
         .ok_or(VerificationError::InvalidLimits)?;
      let message_bytes = arguments
         .next()
         .and_then(|argument| argument.to_str()?.parse().ok())
         .ok_or(VerificationError::InvalidLimits)?;
      if arguments.next().is_some() || matches!(address_space, 0 | u64::MAX) || message_bytes == 0 {
         return Err(VerificationError::InvalidLimits);
      }
      worker_process::serve(address_space, message_bytes)?;
      Ok(true)
   }
   #[cfg(not(target_os = "linux"))]
   {
      Err(VerificationError::UnsupportedPlatform)
   }
}
