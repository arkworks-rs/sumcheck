use algebra_core::{CanonicalSerialize, Field, ToBytes};
#[allow(unused_imports)]
use ark_std::vec::Vec;
use blake2::{Blake2s, Digest};
use rand_core::{Error, RngCore};

use crate::data_structures::random::{FeedableRNG, RnFg};

/// Convert any RngCore to Feedable RNG (feed is no-op)
pub struct AsDummyFeedable<R: RngCore> {
    rng: R,
}

impl<R: RngCore> RngCore for AsDummyFeedable<R> {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.rng.try_fill_bytes(dest)
    }
}

impl<R: RngCore> AsDummyFeedable<R> {
    /// constructor
    pub fn new(rng: R) -> Self {
        Self { rng }
    }
}

impl<R: RngCore> From<R> for AsDummyFeedable<R> {
    fn from(rng: R) -> Self {
        Self::new(rng)
    }
}

impl<R: RngCore> FeedableRNG for AsDummyFeedable<R> {
    type Error = crate::Error;

    fn setup() -> Self {
        unimplemented!("Call `new` or `from` instead")
    }

    /// no-op
    #[inline]
    fn feed<M: ToBytes>(&mut self, _msg: &M) -> Result<(), Self::Error> {
        Ok(())
    }

    /// no-op
    fn feed_randomness<M: CanonicalSerialize>(&mut self, _msg: &M) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// 512-bits digest hash pseudorandom generator
pub struct Blake2s512Rng {
    /// current digest instance
    current_digest: Blake2s,
}

impl FeedableRNG for Blake2s512Rng {
    type Error = crate::Error;

    fn setup() -> Self {
        Self {
            current_digest: Blake2s::new(),
        }
    }

    fn feed<M: ToBytes>(&mut self, msg: &M) -> Result<(), Self::Error> {
        let mut buf = Vec::new();
        msg.write(&mut buf)?;
        self.current_digest.update(&buf);
        Ok(())
    }

    fn feed_randomness<M: CanonicalSerialize>(&mut self, msg: &M) -> Result<(), Self::Error> {
        let mut buf = Vec::new();
        msg.serialize(&mut buf)?;
        self.current_digest.update(&buf);
        Ok(())
    }
}

impl RngCore for Blake2s512Rng {
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

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        let mut digest = self.current_digest.clone();
        let mut output = digest.finalize();
        let output_size = Blake2s::output_size();
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

impl<G: RngCore, F: Field> RnFg<F> for G {
    fn random_field(&mut self) -> F {
        F::rand(self)
    }
}

#[cfg(test)]
mod tests {
    use crate::data_structures::impl_random::Blake2s512Rng;
    use crate::data_structures::random::tests::test_deterministic_pseudorandom_generator;
    use crate::data_structures::test_field::TestField;

    type F = TestField;

    #[test]
    fn test_blake2s_hashing() {
        test_deterministic_pseudorandom_generator::<Blake2s512Rng, F>(5)
    }
}
