//! Error used for ML Commitment Scheme
use ark_std::fmt;
use ark_std::fmt::Formatter;
use ark_std::string::String;
#[derive(Debug)]
/// Error used for ML Commitment Scheme
pub enum Error {
    /// bad argument
    InvalidArgument(Option<String>),
    /// serialization error
    SerializationError(ark_serialize::SerializationError),
    /// others
    MLExtensionError(linear_sumcheck::Error),
}

/// result used for this crate
pub type SResult<T> = Result<T, Error>;

/// invalid argument error
pub fn invalid_arg(msg: &str) -> Error {
    Error::InvalidArgument(Some(msg.into()))
}

impl fmt::Display for Error {
    fn fmt(&self, _f: &mut Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl From<linear_sumcheck::Error> for Error {
    fn from(e: linear_sumcheck::Error) -> Self {
        Error::MLExtensionError(e)
    }
}

impl From<ark_serialize::SerializationError> for Error {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Error::SerializationError(e)
    }
}
