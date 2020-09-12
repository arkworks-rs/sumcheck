use core::fmt;

use algebra::alloc::fmt::Formatter;

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

impl algebra::Error for Error {}
