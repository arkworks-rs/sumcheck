//! Fiat-Shamir Random Generator
use ark_serialize::CanonicalSerialize;
use ark_std::rand::RngCore;
use ark_std::vec::Vec;
use blake2::{Blake2b512, Digest};
/// Random Field Element Generator where randomness `feed` adds entropy for the output.
///
/// Implementation should support all types of input that has `ToBytes` trait.
///
/// Same sequence of `feed` and `get` call should yield same result!
pub trait FeedableRNG: RngCore {
    /// Error type
    type Error: ark_std::error::Error + From<crate::Error>;
    /// Setup should not have any parameter.
    fn setup() -> Self;

    /// Provide randomness for the generator, given the message.
    fn feed<M: CanonicalSerialize>(&mut self, msg: &M) -> Result<(), Self::Error>;
}

/// 512-bits digest hash pseudorandom generator
pub struct Blake2b512Rng {
    /// current digest instance
    current_digest: Blake2b512,
}

impl FeedableRNG for Blake2b512Rng {
    type Error = crate::Error;

    fn setup() -> Self {
        Self {
            current_digest: Blake2b512::new(),
        }
    }

    fn feed<M: CanonicalSerialize>(&mut self, msg: &M) -> Result<(), Self::Error> {
        let mut buf = Vec::new();
        msg.serialize_uncompressed(&mut buf)?;
        self.current_digest.update(&buf);
        Ok(())
    }
}

impl RngCore for Blake2b512Rng {
    fn next_u32(&mut self) -> u32 {
        let mut temp = [0u8; 4];
        self.fill_bytes(&mut temp);
        u32::from_le_bytes(temp)
    }

    fn next_u64(&mut self) -> u64 {
        let mut temp = [0u8; 8];
        self.fill_bytes(&mut temp);
        u64::from_le_bytes(temp)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest).unwrap()
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), ark_std::rand::Error> {
        let mut digest = self.current_digest.clone();
        let mut output = digest.finalize();
        let output_size = Blake2b512::output_size();
        let mut ptr = 0;
        let mut digest_ptr = 0;
        while ptr < dest.len() {
            dest[ptr] = output[digest_ptr];
            ptr += 1usize;
            digest_ptr += 1;
            if digest_ptr == output_size {
                self.current_digest.update(output);
                digest = self.current_digest.clone();
                output = digest.finalize();
                digest_ptr = 0;
            }
        }
        self.current_digest.update(output);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::Field;
    use ark_std::rand::Rng;
    use ark_std::rand::RngCore;

    use crate::rng::{Blake2b512Rng, FeedableRNG};
    use ark_serialize::CanonicalSerialize;
    use ark_std::test_rng;
    use ark_std::vec::Vec;
    use ark_test_curves::bls12_381::Fr;

    /// Special type of input used for test.
    #[derive(CanonicalSerialize)]
    struct TestMessage {
        data: Vec<u8>,
    }

    impl TestMessage {
        fn rand<R: RngCore>(rng: &mut R, size: usize) -> TestMessage {
            let mut data = Vec::with_capacity(size);
            data.resize_with(size, || rng.gen());
            TestMessage { data }
        }
    }

    /// Test that same sequence of `feed` and `get` call should yield same result.
    ///
    /// * `rng_test`: the pseudorandom RNG to be tested
    /// * `num_iterations`: number of independent tests
    fn test_deterministic_pseudorandom_generator<G, F>(num_iterations: u32)
    where
        F: Field,
        G: FeedableRNG,
    {
        let mut rng = test_rng();
        for _ in 0..num_iterations {
            // generate write messages
            let mut msgs = Vec::with_capacity(7);
            msgs.resize_with(7, || TestMessage::rand(&mut rng, 128));

            let rw_sequence = |r: &mut G, o: &mut Vec<F>| {
                r.feed(&msgs[0]).unwrap();
                o.push(F::rand(r));
                o.push(F::rand(r));
                r.feed(&msgs[1]).unwrap();
                r.feed(&msgs[2]).unwrap();
                o.push(F::rand(r));
                r.feed(&msgs[3]).unwrap();
                o.push(F::rand(r));
                o.push(F::rand(r));
                r.feed(&msgs[4]).unwrap();
                r.feed(&msgs[5]).unwrap();
                r.feed(&msgs[6]).unwrap();
                let f1 = F::rand(r);
                o.push(f1);
                let f2 = F::rand(r);
                o.push(f2);
                assert_ne!(f1, f2, "Producing same element");
                o.push(F::rand(r));
                o.push(F::rand(r));
                // edge case: not aligned bytes
                let mut buf1 = [0u8; 127];
                let mut buf2 = [0u8; 128];
                let mut buf3 = [0u8; 777];
                r.fill_bytes(&mut buf1);
                r.feed(&buf1.to_vec()).unwrap();
                r.fill_bytes(&mut buf2);
                r.fill_bytes(&mut buf3);
                assert_ne!(&buf2[..64], &buf3[..64]);
                o.push(F::rand(r));
                r.feed(&buf3.to_vec()).unwrap();
                o.push(F::rand(r));
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

    #[test]
    fn test_blake2s_hashing() {
        test_deterministic_pseudorandom_generator::<Blake2b512Rng, Fr>(5)
    }
}
