#![allow(unreachable_pub)]
use std::fmt::{Debug, Display};

use algebra::{CanonicalDeserialize, CanonicalSerialize, ToBytes};

use crate::error::Error;

/// Message that is transferred between protocols. The message can be (de)serialized and
/// can be converted to bytes deterministically.
pub trait Message:
    CanonicalSerialize + CanonicalDeserialize + ToBytes + Clone
{
    // nothing required
}

/// Interactive protocol
pub trait Protocol: Sized {
    /// Message sent **to** this protocol from others.
    type InboundMessage: Message;
    /// Message sent **from** this protocol to others.
    type OutBoundMessage: Message;
    /// Type of error
    type Error: algebra::Error + From<Error> + Display;

    /// Get current round.
    /// If the protocol is not active (e.g. in accepted or rejected status), `current_round`
    /// should return an InvalidOperationError.
    fn current_round(&self) -> Result<u32, Self::Error>;

    /// If this method is true, user can push message to this protocol at this time.
    ///
    /// Note: inactive doesn't mean user cannot get latest message.
    fn is_active(&self) -> bool;

    /// Get message from this protocol at round
    ///
    /// If round < current round, the protocol simply returns message from cache.
    /// If the protocol does not support cache, this protocol will return an error.
    fn get_message(&self, round: u32) -> Result<Self::OutBoundMessage, Self::Error>;

    /// get message from this protocol at current round
    ///
    /// Repeatedly calling `get_latest_message` without pushing lead to same result.
    fn get_latest_message(&mut self) -> Result<Self::OutBoundMessage, Self::Error> {
        self.get_message(self.current_round()?)
    }

    /// Push message to this protocol
    ///
    /// Protocol goes to next round, or become inactive.
    fn push_message(&mut self, msg: &Self::InboundMessage) -> Result<(), Self::Error>;
}

/// represents the state of verifier
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VerifierState {
    /// The verifier need prover's message to setup.
    #[cfg(test)] // setup is currently not used by main code.
    Setup,
    /// The verifier is listening. It is not yet convinced.
    /// The data includes the round number (from `1` to `2n` inclusive), where `n` is dimension of `x` and `y`.
    Round(u32),

    /// The verifier is convinced of the sum. It is ready to output the sub-claim, which is a point
    /// and its expected evaluation.
    Convinced,

    /// The verifier does not believe the sum is true. The proof is broken.
    Rejected,
}

/// General Verifier Protocol
pub trait VerifierProtocol: Protocol {
    /// Get state of the verifier.
    fn get_state(&self) -> VerifierState;
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::{Duration, Instant};

    use crate::data_structures::protocol::{Message, Protocol, VerifierProtocol, VerifierState};

    /// Make sure the protocol is not broken, and make sure the protocol halts eventually.
    ///
    /// * `alice` - protocol that sends message first
    /// * `bob` - protocol that responds `alice`
    /// * `max_rounds_allowed` - max rounds allowed
    /// * `both_must_end`: - make sure both protocol ends at same time
    /// * `ret`: messages sent by alice and bob
    pub(crate) fn test_communication<P1, P2>(
        mut alice: P1,
        mut bob: P2,
        max_rounds_allowed: u32,
        both_must_end: bool,
    ) -> (Vec<P1::OutBoundMessage>, Vec<P2::OutBoundMessage>)
    where
        P1: Protocol,
        P2: Protocol<InboundMessage = P1::OutBoundMessage, OutBoundMessage = P1::InboundMessage>,
    {
        let mut messages_alice: Vec<P1::OutBoundMessage> = Vec::new();
        let mut messages_bob: Vec<P1::InboundMessage> = Vec::new();

        // test the protocol works
        let mut round = 1;
        while round <= max_rounds_allowed {
            let a = alice.get_message(round).unwrap();
            bob.push_message(&a).unwrap(); // A -> B
            messages_alice.push(a.clone());
            if !bob.is_active() {
                if alice.is_active() && both_must_end {
                    let msg = bob.get_message(round).unwrap();
                    alice.push_message(&msg).unwrap();
                    assert!(!alice.is_active(), "Alice should not be active now. ")
                }
                break;
            }
            let b = bob.get_message(round).unwrap();
            alice.push_message(&b).unwrap(); // A <- B
            messages_bob.push(b.clone());
            round += 1;
        }

        if alice.is_active() || bob.is_active() {
            panic!("Maximum rounds allowed exceeded. ")
        }

        (messages_alice, messages_bob)
    }

    // /// test if two messages are equal using bytes
    // fn test_equal_msg_by_bytes<M: Message>(m1: &M, m2: &M) -> bool {
    //     let m1size = m1.serialized_size();
    //     let m2size = m2.serialized_size();
    //     if m1size != m2size {
    //         return false;
    //     }
    //     let mut buf1 = vec![0u8; m1size];
    //     m1.serialize(&mut buf1).unwrap();
    //     let mut buf2 = vec![0u8; m2size];
    //     m2.serialize(&mut buf2).unwrap();
    //     buf1 == buf2
    // }

    /// Test that the prover-verifier protocol satisfies completeness property.
    ///
    /// * `prover` - protocol that sends message first
    /// * `verifier` - protocol that responds `prover` and acts as a verifier
    /// * `max_rounds_allowed` - max rounds allowed
    /// * `both_must_end`: - make sure both protocol ends at same time
    pub(crate) fn test_protocol_completeness<P, V>(
        prover: &mut P,
        verifier: &mut V,
        max_rounds_allowed: u32,
        both_must_end: bool,
    ) where
        P: Protocol,
        V: VerifierProtocol<
            InboundMessage = P::OutBoundMessage,
            OutBoundMessage = P::InboundMessage,
        >,
    {
        // test the protocol works
        let mut round = 1;
        while round <= max_rounds_allowed {
            if let VerifierState::Round(i) = verifier.get_state() {
                assert_eq!(i, round, "round mismatch") // should be correct state
            } else {
                if VerifierState::Setup != verifier.get_state() {
                    panic!("Invalid verifier state")
                }
            };
            let a = prover.get_message(round).unwrap();
            verifier.push_message(&a).unwrap(); // A -> B

            if !verifier.is_active() {
                if prover.is_active() && both_must_end {
                    let msg = verifier.get_message(round).unwrap();
                    prover.push_message(&msg).unwrap();
                    assert!(!prover.is_active(), "Alice should not be active now. ")
                }
                break;
            }
            let b = verifier.get_message(round).unwrap();
            prover.push_message(&b).unwrap(); // A <- B
            round += 1;
        }

        if prover.is_active() || verifier.is_active() {
            panic!("Maximum rounds allowed exceeded. ")
        }

        assert_eq!(
            verifier.get_state(),
            VerifierState::Convinced,
            "Completeness Broken: verifier is not convinced. \
        Current Status: {:?}",
            verifier.get_state()
        )
    }

    /// Benchmark this protocol.
    ///
    /// * `alice` - protocol that sends message first
    /// * `bob` - protocol that responds `prover` and acts as a verifier
    /// * `max_rounds_allowed` - max rounds allowed
    /// * *return*: `((t_alice_get, t_alice_push), (t_bob_get, t_bob_push))`
    pub(crate) fn test_protocol_benchmark<P, V>(
        mut alice: P,
        mut bob: V,
        max_rounds_allowed: u32,
    ) -> ((Duration, Duration), (Duration, Duration))
    where
        P: Protocol,
        V: Protocol<InboundMessage = P::OutBoundMessage, OutBoundMessage = P::InboundMessage>,
    {
        // test the protocol works
        let mut round = 1;
        let mut t_alice_get = Duration::new(0, 0);
        let mut t_alice_push = Duration::new(0, 0);
        let mut t_bob_get = Duration::new(0, 0);
        let mut t_bob_push = Duration::new(0, 0);
        while round <= max_rounds_allowed {
            let t0 = Instant::now();
            let a = alice.get_message(round).unwrap();
            t_alice_get += Instant::now() - t0;

            let t0 = Instant::now();
            bob.push_message(&a).unwrap(); // A -> B
            t_bob_push += Instant::now() - t0;

            if !bob.is_active() {
                break;
            }
            let t0 = Instant::now();
            let b = bob.get_message(round).unwrap();
            t_bob_get += Instant::now() - t0;

            let t0 = Instant::now();
            alice.push_message(&b).unwrap(); // A <- B
            t_alice_push += Instant::now() - t0;
            round += 1;
        }

        if alice.is_active() || bob.is_active() {
            panic!("Maximum rounds allowed exceeded. ")
        }

        ((t_alice_get, t_alice_push), (t_bob_get, t_bob_push))
    }

    /// Test Message's Serialization works correctly and is deterministic
    /// * `msg`: the message to be tested
    /// * `repeat`: number of additional repeats (to ensure serialization is deterministic).
    /// * `cmp`: comparator testing whether two messages are the same
    pub(crate) fn test_message_serialization<M: Message>(
        msg: M,
        repeat: u32,
        cmp: impl Fn(&M, &M) -> bool,
    ) {
        let mut buf = Vec::with_capacity(msg.serialized_size());
        msg.serialize(&mut buf).unwrap();
        let copied: M = M::deserialize(buf.as_slice()).unwrap();
        assert!(cmp(&msg, &copied));

        for _ in 1..repeat {
            let mut buf2 = Vec::with_capacity(msg.serialized_size());
            msg.serialize(&mut buf2).unwrap();
            assert_eq!(buf, buf2);
        }
    }
}
