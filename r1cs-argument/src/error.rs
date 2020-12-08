use ark_std::fmt;
use ark_std::fmt::Formatter;
use ark_std::string::String;
#[derive(Debug)]
/// Error used for R1CS Argument
pub enum Error {
    /// bad argument
    InvalidArgument(Option<String>),
    /// linear sumcheck error
    SumCheckError(linear_sumcheck::Error),
    /// wrong private witness value
    WrongWitness(Option<String>),
    /// serialization error
    SerializationError(ark_serialize::SerializationError),
    /// Commitment error
    CommitmentError(ml_commitment::Error),
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
        Error::SumCheckError(e)
    }
}

impl From<ark_serialize::SerializationError> for Error {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Error::SerializationError(e)
    }
}

impl From<ml_commitment::Error> for Error {
    fn from(e: ml_commitment::Error) -> Self {
        Error::CommitmentError(e)
    }
}
