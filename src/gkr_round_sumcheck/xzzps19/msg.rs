#[cfg(feature = "std")]
use algebra_core::io::ErrorKind;
use algebra_core::io::{Error as IOError, Read, Result as IOResult, Write};
use algebra_core::{CanonicalDeserialize, CanonicalSerialize, Field, SerializationError, ToBytes};

use crate::data_structures::protocol::Message;

#[derive(Debug, Eq, PartialEq, Clone)]
/// Message used for prover, received by verifier.
pub(crate) struct XZZPS19PMsg<F: Field>(pub(crate) F, pub(crate) F, pub(crate) F);

impl<F: Field> Message for XZZPS19PMsg<F> {}

impl<F: Field> CanonicalSerialize for XZZPS19PMsg<F> {
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        self.0.serialize(&mut writer)?;
        self.1.serialize(&mut writer)?;
        self.2.serialize(&mut writer)?;

        Ok(())
    }

    fn serialized_size(&self) -> usize {
        self.0.serialized_size() * 3
    }
}

impl<F: Field> CanonicalDeserialize for XZZPS19PMsg<F> {
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let p0 = F::read(&mut reader)?;
        let p1 = F::read(&mut reader)?;
        let p2 = F::read(&mut reader)?;
        Ok(XZZPS19PMsg(p0, p1, p2))
    }
}

impl<F: Field> ToBytes for XZZPS19PMsg<F> {
    #[cfg(not(feature = "std"))]
    fn write<W: Write>(&self, writer: W) -> IOResult<()> {
        match self.serialize(writer) {
            Ok(()) => Ok(()),
            Err(_e) => Err(IOError),
        }
    }
    #[cfg(feature = "std")]
    fn write<W: Write>(&self, writer: W) -> IOResult<()> {
        match self.serialize(writer) {
            Ok(()) => Ok(()),
            Err(_e) => Err(IOError::new(
                ErrorKind::InvalidData,
                "Cannot serialize message. ",
            )),
        }
    }
}

/// Message sent from verifier to prover
#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct XZZPS19VMsg<F: Field> {
    /// The fixed argument x
    ///
    /// At round i, `H_i(x) = sum of H(m1, m2, ..., m_(i-1), x, v_(i+1), ... v_2n) over v_(i+1) to v_2n`.
    /// Verifier fix x and send this fixed value.
    pub(crate) x: F,
}

impl<F: Field> Message for XZZPS19VMsg<F> {}

impl<F: Field> CanonicalSerialize for XZZPS19VMsg<F> {
    fn serialize<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        self.x.serialize(writer)
    }

    fn serialized_size(&self) -> usize {
        self.x.serialized_size()
    }
}

impl<F: Field> CanonicalDeserialize for XZZPS19VMsg<F> {
    fn deserialize<R: Read>(reader: R) -> Result<Self, SerializationError> {
        Ok(Self {
            x: F::deserialize(reader)?,
        })
    }
}

impl<F: Field> ToBytes for XZZPS19VMsg<F> {
    #[cfg(not(feature = "std"))]
    fn write<W: Write>(&self, writer: W) -> IOResult<()> {
        match self.serialize(writer) {
            Ok(()) => Ok(()),
            Err(_e) => Err(IOError),
        }
    }
    #[cfg(feature = "std")]
    fn write<W: Write>(&self, writer: W) -> IOResult<()> {
        match self.serialize(writer) {
            Ok(()) => Ok(()),
            Err(_e) => Err(IOError::new(
                ErrorKind::InvalidData,
                "Cannot serialize message. ",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use algebra::{test_rng, UniformRand};

    use crate::data_structures::protocol::tests::test_message_serialization;
    use crate::data_structures::test_field::TestField as TF;
    use crate::gkr_round_sumcheck::xzzps19::msg::{XZZPS19PMsg, XZZPS19VMsg};

    const NUM_ITERATIONS: u32 = 100;

    /// test `read` and `write` works correctly
    #[test]
    fn test_io() {
        let mut rng = test_rng();
        for _ in 0..NUM_ITERATIONS {
            let p0 = TF::rand(&mut rng);
            let p1 = TF::rand(&mut rng);
            let p2 = TF::rand(&mut rng);
            let x = TF::rand(&mut rng);
            let msg = XZZPS19PMsg(p0, p1, p2);
            let msg_v = XZZPS19VMsg { x };
            test_message_serialization(msg, 3, |m1, m2| *m1 == *m2);
            test_message_serialization(msg_v, 3, |m1, m2| *m1 == *m2);
        }
    }
}
