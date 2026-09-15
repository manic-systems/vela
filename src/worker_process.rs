use std::{
   io::{
      self,
      Read as _,
      Write as _,
   },
   net::Shutdown,
   os::{
      fd::OwnedFd,
      unix::net::UnixStream,
   },
   path::Path,
   process::{
      Child,
      Command,
      ExitStatus,
      Stdio,
   },
   thread,
   time::{
      Duration,
      Instant,
   },
};

use rustix::process::{
   Resource as ProcessResource,
   Rlimit,
   getrlimit,
   setrlimit,
};

use crate::{
   verify,
   verify_wire::{
      self,
      Request,
      Response,
   },
   worker::{
      Limits,
      VerificationError,
   },
};

/// Every error path kills and reaps the worker before returning to its caller.
struct Running {
   /// The child handle remains owned until its exit status has been collected.
   child:  Child,
   /// A collected exit status prevents cleanup from signalling a reused PID.
   reaped: bool,
}

impl Drop for Running {
   fn drop(&mut self) {
      if !self.reaped {
         drop(self.child.kill());
         drop(self.child.wait());
      }
   }
}

impl Running {
   /// A valid reply cannot bypass the deadline by leaving the worker running.
   fn finish(&mut self, deadline: Instant) -> Result<ExitStatus, VerificationError> {
      loop {
         remaining(deadline)?;
         if let Some(status) = self
            .child
            .try_wait()
            .map_err(|source| VerificationError::Io { source })?
         {
            self.reaped = true;
            remaining(deadline)?;
            return Ok(status);
         }
         thread::sleep(remaining(deadline)?.min(Duration::from_millis(5)));
      }
   }
}

/// Preloaded allocators such as `hardened_malloc` reserve terabytes before
/// main.
pub fn run(
   executable: &Path,
   limits: Limits,
   message: &[u8],
   deadline: Instant,
) -> Result<Vec<u8>, VerificationError> {
   remaining(deadline)?;
   let (mut parent, child) =
      UnixStream::pair().map_err(|source| VerificationError::Io { source })?;
   let input = child
      .try_clone()
      .map_err(|source| VerificationError::Io { source })?;
   let process = Command::new(executable)
      .env_remove("LD_PRELOAD")
      .env_remove("LD_AUDIT")
      .arg("--vela-verify-worker")
      .arg(limits.address_space_bytes.to_string())
      .arg(limits.message_bytes.to_string())
      .stdin(Stdio::from(OwnedFd::from(input)))
      .stdout(Stdio::from(OwnedFd::from(child)))
      .stderr(Stdio::null())
      .spawn()
      .map_err(|source| VerificationError::Io { source })?;
   let mut running = Running {
      child:  process,
      reaped: false,
   };
   let response = exchange(&mut parent, message, limits.message_bytes, deadline);
   if matches!(
      response,
      Err(VerificationError::Timeout | VerificationError::MessageTooLarge { .. })
   ) {
      return response;
   }
   if response.is_err() {
      if let Some(status) = running
         .child
         .try_wait()
         .map_err(|source| VerificationError::Io { source })?
      {
         running.reaped = true;
         if !status.success() {
            return Err(VerificationError::Exited(status));
         }
      }
      return response;
   }
   let status = running.finish(deadline)?;
   if !status.success() {
      return Err(VerificationError::Exited(status));
   }
   response
}

/// A total deadline is recomputed for each operation so trickled bytes cannot
/// renew it.
fn exchange(
   socket: &mut UnixStream,
   mut message: &[u8],
   limit: usize,
   deadline: Instant,
) -> Result<Vec<u8>, VerificationError> {
   while !message.is_empty() {
      socket
         .set_write_timeout(Some(remaining(deadline)?))
         .map_err(|source| VerificationError::Io { source })?;
      match socket.write(message) {
         Ok(0) => return Err(VerificationError::InvalidReply),
         Ok(written) => message = &message[written..],
         Err(source) if source.kind() == io::ErrorKind::Interrupted => {},
         Err(source) => return Err(transport(source)),
      }
   }
   socket
      .shutdown(Shutdown::Write)
      .map_err(|source| VerificationError::Io { source })?;
   let mut response = Vec::new();
   let mut buffer = [0_u8; 8192];
   loop {
      socket
         .set_read_timeout(Some(remaining(deadline)?))
         .map_err(|source| VerificationError::Io { source })?;
      let size = buffer
         .len()
         .min(limit.saturating_sub(response.len()).saturating_add(1));
      match socket.read(&mut buffer[..size]) {
         Ok(0) => return Ok(response),
         Ok(read) => {
            if read > limit - response.len() {
               return Err(VerificationError::MessageTooLarge { limit });
            }
            response.extend_from_slice(&buffer[..read]);
         },
         Err(source) if source.kind() == io::ErrorKind::Interrupted => {},
         Err(source) => return Err(transport(source)),
      }
   }
}

/// Socket timeout errors represent the shared verification deadline.
fn transport(source: io::Error) -> VerificationError {
   if matches!(
      source.kind(),
      io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
   ) {
      VerificationError::Timeout
   } else {
      VerificationError::Io { source }
   }
}

/// A zero timeout is rejected because socket APIs interpret it differently.
fn remaining(deadline: Instant) -> Result<Duration, VerificationError> {
   deadline
      .checked_duration_since(Instant::now())
      .filter(|duration| !duration.is_zero())
      .ok_or(VerificationError::Timeout)
}

/// Limits are installed after exec and before any request decoding or Wasm
/// parsing.
pub fn serve(address_space: u64, message_bytes: usize) -> Result<(), VerificationError> {
   for (resource, requested) in [
      (ProcessResource::As, address_space),
      (ProcessResource::Core, 0),
   ] {
      let inherited = getrlimit(resource);
      setrlimit(resource, Rlimit {
         current: Some(
            inherited
               .current
               .map_or(requested, |bound| bound.min(requested)),
         ),
         maximum: Some(
            inherited
               .maximum
               .map_or(requested, |bound| bound.min(requested)),
         ),
      })
      .map_err(|source| {
         VerificationError::Io {
            source: source.into(),
         }
      })?;
   }
   let mut bytes = Vec::new();
   let bound = u64::try_from(message_bytes).map_err(|_error| VerificationError::InvalidLimits)?;
   io::stdin()
      .lock()
      .take(bound.saturating_add(1))
      .read_to_end(&mut bytes)
      .map_err(|source| VerificationError::Io { source })?;
   if bytes.len() > message_bytes {
      return Err(VerificationError::MessageTooLarge {
         limit: message_bytes,
      });
   }
   let request = verify_wire::decode::<Request<Vec<u8>, Vec<verify::Action>>>(&bytes)?;
   let compared = request.actions.as_ref().map_or_else(
      || verify::compare(&request.before, &request.after, &request.host),
      |actions| verify::compare_scenario(&request.before, &request.after, actions, &request.host),
   );
   let response = verify_wire::encode(&Response::from(compared), message_bytes)?;
   io::stdout()
      .lock()
      .write_all(&response)
      .map_err(|source| VerificationError::Io { source })?;
   Ok(())
}
