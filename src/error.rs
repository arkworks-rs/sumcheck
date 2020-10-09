use core::fmt;

use algebra_core::String;
use core::fmt::Formatter;
/// Error type for this crate
#[derive(Debug)]
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
    /// Other caused by other operations
    CausedBy(String),
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

impl algebra_core::Error for Error {}

impl From<ark_std::io::Error> for Error {
    fn from(_: ark_std::io::Error) -> Self {
        Self::IOError
    }
}

impl From<algebra_core::SerializationError> for Error {
    fn from(_: algebra_core::SerializationError) -> Self{
        Self::SerializationError
    }
}