use std::error::Error as StdError;

use postcard::experimental::serialized_size;
use serde::{
   Deserialize,
   Deserializer,
   Serialize,
   Serializer,
   de::Error as DeError,
};

use crate::{
   verify::{
      Comparison,
      Error as VerifyError,
      HostConfig,
      ModuleSide,
      Resource,
   },
   worker::VerificationError,
};

/// Client requests borrow slices while the worker owns its decoded copy.
#[derive(Debug, Serialize, Deserialize)]
pub struct Request<Bytes, Actions> {
   /// Unrewritten input provides the comparison reference.
   pub before:  Bytes,
   /// Candidate bytes are executed with the same host as the reference.
   pub after:   Bytes,
   /// Absence selects every zero-argument export.
   pub actions: Option<Actions>,
   /// Both executions receive identical stubs and guest limits.
   pub host:    HostConfig,
}

/// Compared holds worker output while Failed carries a serializable cause.
#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
   /// Completed observations still require comparison by the caller.
   Compared(Vec<Comparison>),
   /// A worker error never represents a completed comparison.
   Failed(Failure),
}

/// Limit preserves budget identity while Verification carries one message.
#[derive(Debug, Serialize, Deserialize)]
pub enum Failure {
   /// Resource exhaustion remains typed across the process boundary.
   Limit {
      /// Identifies the module whose budget was exhausted.
      side:     ModuleSide,
      /// Identifies the exhausted budget for caller handling.
      resource: Resource,
   },
   /// Interpreter failures retain their displayed cause chain.
   Verification {
      /// Display text includes each nested error source.
      message: String,
   },
}

/// Encodes the trap discriminant without duplicating the wasmi enum.
#[inline]
#[expect(
   clippy::trivially_copy_pass_by_ref,
   reason = "serde helper takes the discriminant by reference"
)]
pub fn serialize_trap<Ser>(code: &wasmi::TrapCode, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
where
   Ser: Serializer,
{
   serializer.serialize_u8(u8::from(*code))
}

/// Decodes the trap discriminant and rejects values outside the wasmi enum.
#[inline]
pub fn deserialize_trap<'de, De>(deserializer: De) -> Result<wasmi::TrapCode, De::Error>
where
   De: Deserializer<'de>,
{
   let discriminant = u8::deserialize(deserializer)?;
   wasmi::TrapCode::try_from(discriminant)
      .map_err(|_invalid| DeError::custom(format!("unknown trap code {discriminant}")))
}

/// Encodes below the transport limit and reports oversize before allocating.
#[inline]
pub fn encode<Message>(value: &Message, limit: usize) -> Result<Vec<u8>, VerificationError>
where
   Message: Serialize + ?Sized,
{
   let size = serialized_size(value).map_err(|source| VerificationError::Codec { source })?;
   if size > limit {
      return Err(VerificationError::MessageTooLarge { limit });
   }
   postcard::to_stdvec(value).map_err(|source| VerificationError::Codec { source })
}

/// Decodes owned values and rejects trailing bytes after one message.
#[inline]
pub fn decode<Message>(bytes: &[u8]) -> Result<Message, VerificationError>
where
   Message: for<'de> Deserialize<'de>,
{
   let (value, rest) =
      postcard::take_from_bytes(bytes).map_err(|source| VerificationError::Codec { source })?;
   if rest.is_empty() {
      Ok(value)
   } else {
      Err(VerificationError::InvalidReply)
   }
}

impl From<Result<Vec<Comparison>, VerifyError>> for Response {
   #[inline]
   fn from(result: Result<Vec<Comparison>, VerifyError>) -> Self {
      match result {
         Ok(comparisons) => Self::Compared(comparisons),
         Err(VerifyError::LimitExceeded { side, resource }) => {
            Self::Failed(Failure::Limit { side, resource })
         },
         Err(error) => {
            Self::Failed(Failure::Verification {
               message: error_message(&error),
            })
         },
      }
   }
}

impl TryFrom<Response> for Vec<Comparison> {
   type Error = VerificationError;

   #[inline]
   fn try_from(response: Response) -> Result<Self, Self::Error> {
      match response {
         Response::Compared(comparisons) => Ok(comparisons),
         Response::Failed(Failure::Limit { side, resource }) => {
            Err(VerificationError::LimitExceeded { side, resource })
         },
         Response::Failed(Failure::Verification { message }) => {
            Err(VerificationError::Verification { message })
         },
      }
   }
}

/// Joins the display text with each error source on its own line.
fn error_message(error: &VerifyError) -> String {
   let mut message = error.to_string();
   let mut source = StdError::source(error);
   while let Some(next) = source {
      message.push('\n');
      message.push_str(&next.to_string());
      source = StdError::source(next);
   }
   message
}
