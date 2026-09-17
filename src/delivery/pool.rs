use std::{
   collections::{
      HashMap,
      VecDeque,
   },
   io,
   num::NonZeroUsize,
   sync::{
      Arc,
      Condvar,
      Mutex,
      MutexGuard,
   },
   thread::{
      self,
      JoinHandle,
   },
   time::{
      Duration,
      Instant,
   },
};

use thiserror::Error;

use crate::{
   delivery::artifact::{
      Compression,
      PreparationError,
      Variant,
      VariantId,
   },
   prepare::Prepared,
};

#[derive(Debug, Clone, Copy)]
pub struct Limits {
   pub ready:    NonZeroUsize,
   pub issued:   NonZeroUsize,
   pub lifetime: Duration,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DeliveryError {
   #[error("variant lifetime must be nonzero and representable by the monotonic clock")]
   Lifetime,
   #[error("starting the variant producer")]
   Spawn(#[source] io::Error),
   #[error("no prepared variants are ready")]
   Empty,
   #[error("issued variants have reached their retention limit")]
   Full,
   #[error("the variant producer failed")]
   Producer(#[source] Arc<Failure>),
   #[error("the variant producer stopped unexpectedly")]
   Stopped,
   #[error("the ready queue did not fill before the deadline")]
   Timeout,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Failure {
   #[error("preparing a delivery variant")]
   Prepare(#[source] PreparationError),
   #[error("the seed range is exhausted")]
   SeedExhausted,
   #[error("rewriting produced a duplicate live variant")]
   Duplicate,
}

#[derive(Debug)]
pub struct Status {
   pub ready:   usize,
   pub issued:  usize,
   pub failure: Option<Arc<Failure>>,
}

/// Dropping the pool joins its worker after any in-flight preparation finishes.
pub struct Pool {
   /// Readers and the producer share ownership until the worker joins.
   shared: Arc<Shared>,
   /// Taking the handle makes shutdown join exactly once.
   worker: Option<JoinHandle<()>>,
   /// Issuance cannot evict a URL whose lifetime has not elapsed.
   limits: Limits,
}

/// The worker never holds this mutex while rewriting or compressing.
struct Shared {
   /// A variant moves from ready to issued under this single lock.
   state: Mutex<State>,
   /// Issuance wakes the producer and publication wakes startup waiters.
   wake:  Condvar,
}

/// Expiry starts at issuance, so time in the ready queue cannot shorten a URL's
/// lifetime.
#[derive(Default)]
struct State {
   /// Only the producer inserts here, only issuance removes.
   ready:     VecDeque<Arc<Variant>>,
   /// Fetching never consumes or extends an issued variant.
   issued:    HashMap<VariantId, (Instant, Arc<Variant>)>,
   /// Equal lifetimes and serialized issuance keep deadlines in FIFO order.
   deadlines: VecDeque<(Instant, VariantId)>,
   /// A terminal failure stops production but leaves expiry running.
   failure:   Option<Arc<Failure>>,
   /// Drop sets this before joining the worker.
   stopping:  bool,
}

impl Pool {
   /// The caller supplies a fresh seed range for each pool or deployment.
   ///
   /// # Errors
   ///
   /// Returns invalid lifetime or thread creation errors. Preparation failures
   /// appear through [`Self::status`] and [`Self::issue`].
   #[inline]
   pub fn spawn(
      input: Prepared,
      compression: Compression,
      limits: Limits,
      first_seed: u64,
   ) -> Result<Self, DeliveryError> {
      if limits.lifetime.is_zero() || Instant::now().checked_add(limits.lifetime).is_none() {
         return Err(DeliveryError::Lifetime);
      }

      let shared = Arc::new(Shared {
         state: Mutex::new(State::default()),
         wake:  Condvar::new(),
      });
      let producer = Arc::clone(&shared);
      let worker = thread::Builder::new()
         .name("vela-variants".to_owned())
         .spawn(move || produce(&input, compression, limits, first_seed, &producer))
         .map_err(DeliveryError::Spawn)?;

      Ok(Self {
         shared,
         worker: Some(worker),
         limits,
      })
   }

   /// Empty or full pools never fall back to rewriting on the calling thread.
   ///
   /// # Errors
   ///
   /// Returns capacity or producer errors without issuing a reused variant.
   #[inline]
   pub fn issue(&self) -> Result<Arc<Variant>, DeliveryError> {
      let mut state = self.lock()?;

      if state.issued.len() >= self.limits.issued.get() {
         return Err(DeliveryError::Full);
      }

      let deadline = Instant::now()
         .checked_add(self.limits.lifetime)
         .ok_or(DeliveryError::Lifetime)?;
      let Some(variant) = state.ready.pop_front() else {
         return Err(self.unavailable(&state));
      };
      let id = variant.id();
      state.issued.insert(id, (deadline, Arc::clone(&variant)));
      state.deadlines.push_back((deadline, id));
      drop(state);
      self.shared.wake.notify_all();
      Ok(variant)
   }

   /// Repeated fetches retain one identity until expiry, including HEAD and
   /// retries.
   ///
   /// # Errors
   ///
   /// Returns an error if the worker poisoned the shared state.
   #[inline]
   pub fn get(&self, id: VariantId) -> Result<Option<Arc<Variant>>, DeliveryError> {
      let state = self.lock()?;
      Ok(state
         .issued
         .get(&id)
         .filter(|entry| entry.0 > Instant::now())
         .map(|entry| Arc::clone(&entry.1)))
   }

   /// Terminal failures do not invalidate variants that have already been
   /// issued.
   ///
   /// # Errors
   ///
   /// Returns an error if the worker stopped without recording a preparation
   /// failure.
   #[inline]
   pub fn status(&self) -> Result<Status, DeliveryError> {
      let state = self.lock()?;

      if state.failure.is_none() && self.worker.as_ref().is_none_or(JoinHandle::is_finished) {
         return Err(DeliveryError::Stopped);
      }

      Ok(Status {
         ready:   state.ready.len(),
         issued:  state.issued.len(),
         failure: state.failure.as_ref().map(Arc::clone),
      })
   }

   /// Startup may wait for a full queue, but issuance and lookup never do.
   ///
   /// # Errors
   ///
   /// Returns a timeout or producer failure without selecting a fallback.
   #[inline]
   pub fn wait_ready(&self, timeout: Duration) -> Result<(), DeliveryError> {
      let (state, _) = self
         .shared
         .wake
         .wait_timeout_while(self.lock()?, timeout, |state| {
            state.ready.len() < self.limits.ready.get()
               && state.failure.is_none()
               && !state.stopping
         })
         .map_err(|_poisoned| DeliveryError::Stopped)?;

      if state.ready.len() == self.limits.ready.get() {
         return Ok(());
      }

      let error = self.unavailable(&state);
      drop(state);

      Err(if matches!(error, DeliveryError::Empty) {
         DeliveryError::Timeout
      } else {
         error
      })
   }

   /// Poison means a producer invariant failed, not a recoverable empty pool.
   fn lock(&self) -> Result<MutexGuard<'_, State>, DeliveryError> {
      self
         .shared
         .state
         .lock()
         .map_err(|_poisoned| DeliveryError::Stopped)
   }

   /// A recorded cause survives after the producer stops making variants.
   fn unavailable(&self, state: &State) -> DeliveryError {
      state.failure.as_ref().map_or_else(
         || {
            if self.worker.as_ref().is_none_or(JoinHandle::is_finished) {
               DeliveryError::Stopped
            } else {
               DeliveryError::Empty
            }
         },
         |failure| DeliveryError::Producer(Arc::clone(failure)),
      )
   }
}

impl Drop for Pool {
   #[inline]
   fn drop(&mut self) {
      if let Ok(mut state) = self.shared.state.lock() {
         state.stopping = true;
         self.shared.wake.notify_all();
      }

      if let Some(worker) = self.worker.take() {
         let _result = worker.join();
      }
   }
}

/// Retained URLs expire even after a terminal preparation failure.
fn produce(
   input: &Prepared,
   compression: Compression,
   limits: Limits,
   first_seed: u64,
   shared: &Shared,
) {
   let mut next_seed = Some(first_seed);

   loop {
      let Ok(mut state) = shared.state.lock() else {
         return;
      };

      loop {
         let now = Instant::now();

         while state.deadlines.front().is_some_and(|entry| entry.0 <= now) {
            if let Some((_, expired)) = state.deadlines.pop_front() {
               state.issued.remove(&expired);
            }
         }

         if state.stopping {
            return;
         }

         if state.failure.is_none() && state.ready.len() < limits.ready.get() {
            break;
         }

         state = match if let Some(&(deadline, _)) = state.deadlines.front() {
            shared
               .wake
               .wait_timeout(state, deadline.saturating_duration_since(now))
               .map(|result| result.0)
               .map_err(|_poisoned| ())
         } else {
            shared.wake.wait(state).map_err(|_poisoned| ())
         } {
            Ok(awake) => awake,
            Err(()) => return,
         };
      }

      let Some(seed) = next_seed else {
         state.failure = Some(Arc::new(Failure::SeedExhausted));
         shared.wake.notify_all();
         continue;
      };
      drop(state);
      let prepared = Variant::prepare(input, seed, compression);
      let Ok(mut output) = shared.state.lock() else {
         return;
      };

      if output.stopping {
         return;
      }

      let variant = match prepared {
         Ok(variant) => variant,
         Err(error) => {
            output.failure = Some(Arc::new(Failure::Prepare(error)));
            shared.wake.notify_all();
            continue;
         },
      };

      if output.issued.contains_key(&variant.id())
         || output.ready.iter().any(|ready| ready.id() == variant.id())
      {
         output.failure = Some(Arc::new(Failure::Duplicate));
         shared.wake.notify_all();
         continue;
      }

      output.ready.push_back(Arc::new(variant));
      drop(output);
      shared.wake.notify_all();
      next_seed = seed.checked_add(1);
   }
}
