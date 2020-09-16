use algebra_core::io::Result as IOResult;
use algebra_core::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use algebra_core::{Field, ToBytes};

use crate::data_structures::protocol::Message;
use algebra_core::vec::Vec;
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub(crate) struct MLLibraPMsg<F: Field> {
    /// evaluations on P(0), P(1), P(2), ...
    pub(crate) evaluations: Vec<F>,
}

impl<F: Field> Message for MLLibraPMsg<F> {}

impl<F: Field> ToBytes for MLLibraPMsg<F> {
    fn write<W: Write>(&self, writer: W) -> IOResult<()> {
        self.evaluations.write(writer)
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub(crate) struct MLLibraVMsg<F: Field> {
    pub(crate) x: F,
}

impl<F: Field> Message for MLLibraVMsg<F> {}

impl<F: Field> ToBytes for MLLibraVMsg<F> {
    fn write<W: Write>(&self, writer: W) -> IOResult<()> {
        self.x.write(writer)
    }
}
