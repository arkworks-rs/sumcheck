use ark_std::fmt;

use ark_std::string::String;
use core::fmt::Formatter;
/// Error type for this crate
#[derive(fmt::Debug)]
pub enum Error {
    /// This operation is meaningless or not allowed in current state.
    InvalidOperationError(Option<String>),
    /// The argument is malformed.
    InvalidArgumentError(Option<String>),
    /// Internal data structure corruption. Something wrong happens inside.
    InternalDataStructureCorruption(Option<String>),
    /// protocol rejects this proof
    Reject(Option<String>),
    /// IO Error
    IOError,
    /// Serialization Error
    SerializationError,
    /// Random Generator Error
    RNGError,
    /// Other caused by other operations
    CausedBy(String),
}

pub(crate) fn invalid_args(msg: &str) -> Error {
    Error::InvalidArgumentError(Some(msg.into()))
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Self::CausedBy(s) = self {
            f.write_str(s)
        } else {
            f.write_fmt(format_args!("{:?}", self))
        }
    }
}

impl ark_std::error::Error for Error {}

impl From<ark_std::io::Error> for Error {
    fn from(_: ark_std::io::Error) -> Self {
        Self::IOError
    }
}

impl From<ark_serialize::SerializationError> for Error {
    fn from(_: ark_serialize::SerializationError) -> Self {
        Self::SerializationError
    }
}
impl From<rand::Error> for Error {
    fn from(_: rand::Error) -> Self {
        Self::RNGError
    }
}
