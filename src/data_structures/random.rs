use algebra_core::{Error, Field, ToBytes, CanonicalSerialize};
use rand_core::RngCore;

/// Random Field Element Generator
pub trait RnFg<F: Field>: Sized + RngCore {
    /// Get an unpredictable field element.
    fn random_field(&mut self) -> F;
}

/// Random Field Element Generator where randomness `feed` adds entropy for the output.
///
/// Implementation should support all types of input that has `ToBytes` trait.
///
/// Same sequence of `feed` and `get` call should yield same result!
pub trait FeedableRNG: RngCore {
    /// Error type
    type Error: Error + From<crate::Error>;
    /// Setup should not have any parameter.
    fn setup() -> Self;

    /// The feed message provide randomness for the generator, given the message.
    /// (This function will be eventually replaced by `feed_randomness`)
    fn feed<M: ToBytes>(&mut self, msg: &M) -> Result<(), Self::Error>;

    /// Provide randomness for the generator, given the message.
    fn feed_randomness<M: CanonicalSerialize>(&mut self, msg: &M) -> Result<(), Self::Error>;
}

#[cfg(test)]
pub mod tests {
    use algebra::io::{Result as IOResult, Write};
    use algebra::test_rng;
    use algebra::{Field, ToBytes};
    use rand::Rng;
    use rand_core::RngCore;

    use crate::data_structures::random::{FeedableRNG, RnFg};
    use algebra_core::vec::Vec;
    /// Special type of input used for test.
    pub struct TestMessage {
        data: Vec<u8>,
    }

    impl TestMessage {
        pub fn rand<R: RngCore>(rng: &mut R, size: usize) -> TestMessage {
            let mut data = Vec::with_capacity(size);
            data.resize_with(size, || rng.gen());
            TestMessage { data }
        }
    }

    impl ToBytes for TestMessage {
        fn write<W: Write>(&self, writer: W) -> IOResult<()> {
            self.data.write(writer)?;
            Ok(())
        }
    }

    /// Test that same sequence of `feed` and `get` call should yield same result.
    ///
    /// * `rng_test`: the pseudorandom RNG to be tested
    /// * `num_iterations`: number of independent tests
    pub fn test_deterministic_pseudorandom_generator<G, F>(num_iterations: u32)
    where
        F: Field,
        G: FeedableRNG + RnFg<F>,
    {
        let mut rng = test_rng();
        for _ in 0..num_iterations {
            // generate write messages
            let mut msgs = Vec::with_capacity(7);
            msgs.resize_with(7, || TestMessage::rand(&mut rng, 128));

            let rw_sequence = |r: &mut G, o: &mut Vec<F>| {
                r.feed(&msgs[0]).unwrap();
                o.push(r.random_field());
                o.push(r.random_field());
                r.feed(&msgs[1]).unwrap();
                r.feed(&msgs[2]).unwrap();
                o.push(r.random_field());
                r.feed(&msgs[3]).unwrap();
                o.push(r.random_field());
                o.push(r.random_field());
                r.feed(&msgs[4]).unwrap();
                r.feed(&msgs[5]).unwrap();
                r.feed(&msgs[6]).unwrap();
                let f1 = r.random_field();
                o.push(f1);
                let f2 = r.random_field();
                o.push(f2);
                assert_ne!(f1, f2, "Producing same element");
                o.push(r.random_field());
                o.push(r.random_field());
                // edge case: not aligned bytes
                let mut buf1 = [0u8; 127];
                let mut buf2 = [0u8; 128];
                let mut buf3 = [0u8; 777];
                r.fill_bytes(&mut buf1);
                r.feed(&buf1.to_vec()).unwrap();
                r.fill_bytes(&mut buf2);
                r.fill_bytes(&mut buf3);
                assert_ne!(&buf2[..64], &buf3[..64]);
                o.push(r.random_field());
                r.feed(&buf3.to_vec()).unwrap();
                o.push(r.random_field());
            };
            let mut rng_test = G::setup();
            let mut random_output = Vec::with_capacity(8);

            rw_sequence(&mut rng_test, &mut random_output);

            // test that it is deterministic
            for _ in 0..10 {
                let mut another_rng_test = G::setup();
                let mut another_random_output = Vec::with_capacity(8);
                rw_sequence(&mut another_rng_test, &mut another_random_output);
                assert_eq!(random_output, another_random_output);
            }
        }
    }
}
