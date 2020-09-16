use algebra_core::Field;

use crate::data_structures::ml_extension::{GKRFunction, MLExtension, SparseMLExtension};
use crate::data_structures::protocol::Protocol;
use crate::data_structures::GKRAsLink;
use crate::gkr_round_sumcheck::xzzps19::msg::{XZZPS19PMsg, XZZPS19VMsg};
use crate::gkr_round_sumcheck::Prover;

/// XZZPS19 implementation of GKR sumcheck prover
pub(crate) struct XZZPS19Prover<'a, F, S, D>
where
    F: Field,
    S: SparseMLExtension<F>,
    D: MLExtension<F>,
{
    f1: &'a S,
    f2: &'a D,
    f3: &'a D,
    g: Vec<F>,
    dim: usize,
    a_hg: Option<Vec<F>>,
    // cache for phase one
    dp_g: Option<Vec<F>>,
    // cache for phase two
    dict_f1: Option<Vec<(S::BinaryArg, F)>>,
    // cache for init phase two
    f2_table: Option<Vec<F>>,
    // cache for phase two
    sum: F,
    u: Vec<F>,
    // randomness received in phase one
    v: Vec<F>,
    // randomness received in phase two
    a_f1: Option<Vec<F>>,
    // cache for phase two
    a_f3_f2u: Option<Vec<F>>,
    // cache for phase two
    messages: Vec<XZZPS19PMsg<F>>, // record the messages sent by prover
}

impl<'a, F, S, D> XZZPS19Prover<'a, F, S, D>
where
    F: Field,
    S: SparseMLExtension<F>,
    D: MLExtension<F>,
{
    /// initialize a_hg for phase one. Should be called in constructor.
    fn initialize_phase_one(&mut self) -> Result<(), crate::Error> {
        let a_f3 = unwrap_safe!(self.f3.table());
        let mut a_hg = Vec::with_capacity(1 << self.dim);
        a_hg.resize(1 << self.dim, F::zero());
        let big_g = precompute(&self.g);

        // rely on sparsity
        let dict_f1 = unwrap_safe!(self.f1.sparse_table());
        for (arg, ev) in dict_f1.iter() {
            let (z, x, y) = three_split((*arg).into(), self.dim);
            let entry = extract_safe!(a_hg.get_mut(x));
            *entry = *entry + big_g[z] * ev * a_f3[y];
        }
        self.dict_f1 = Some(dict_f1);
        self.f2_table = Some(unwrap_safe!(self.f2.table()));
        self.dp_g = Some(big_g);
        self.sum = sum_of_gkr(&a_hg, self.f2_table.as_ref().unwrap());
        self.a_hg = Some(a_hg);
        Ok(())
    }

    fn initialize_phase_two(&mut self) -> Result<(), crate::Error> {
        // address f2u
        {
            let p1 = self.a_hg.as_mut().unwrap(); // should be initialized
            let p2 = self.f2_table.as_mut().unwrap(); // should be initialized
            let r = if let Some(r) = self.u.get(self.dim - 1) {
                *r
            } else {
                return Err(crate::Error::InvalidOperationError(Some(
                    format!("Attempt to get message at round {} without pushing message at previous round. ", self.dim + 1))));
            };
            Self::single_round_2mf_fix(p1, p2, self.dim, self.dim, r); // fix for last round
            let f2u = p2[0];
            let a_f3_f2u: Vec<F> = unwrap_safe!(self.f3.table())
                .iter()
                .map(|x| *x * f2u)
                .collect();
            self.a_f3_f2u = Some(a_f3_f2u);

            // clean cache for a_hg, f2_table
            self.a_hg = None;
            self.f2_table = None;
        }

        let big_g = self.dp_g.as_ref().unwrap();
        let big_u = precompute(&self.u);

        assert_safe!(big_g.len() == big_u.len());
        let mut a_f1 = Vec::with_capacity(1 << self.dim);
        a_f1.resize(1 << self.dim, F::zero());
        for (arg, ev) in self.dict_f1.as_ref().unwrap().iter() {
            let (z, x, y) = three_split((*arg).into(), self.dim);
            a_f1[y] += big_g[z] * big_u[x] * (*ev)
        }

        self.a_f1 = Some(a_f1);

        // clean up
        {
            self.dp_g = None;
            self.dict_f1 = None;
        }
        Ok(())
    }

    /// assume the prover is in phase 1. Push messages to the message stack.
    fn phase1_talk(&mut self) -> Result<(), crate::Error> {
        let round = self.messages.len() + 1;
        let p1 = self.a_hg.as_mut().unwrap(); // should be initialized
        let p2 = self.f2_table.as_mut().unwrap(); // should be initialized

        // fix p1, p2 on r pushed last round
        if round != 1 {
            let r = if let Some(r) = self.u.get(round - 2) {
                *r
            } else {
                return Err(crate::Error::InvalidOperationError(Some(
                    format!("Attempt to get message at round {} without pushing message at previous round. ", round))));
            };
            Self::single_round_2mf_fix(p1, p2, self.dim, round - 1, r); // fix for last round
        }
        let msg = Self::single_round_2pmf_sum(p1, p2, self.dim, round);

        // do not clean cache, as it will be used in init phase 2
        self.messages.push(msg); // current round++

        Ok(())
    }

    fn phase2_talk(&mut self) -> Result<(), crate::Error> {
        let round_in_phase = self.messages.len() + 1 - self.dim;
        // if it is the first round, initialize phase two.
        if round_in_phase == 1 {
            unwrap_safe!(self.initialize_phase_two());
        }

        let p1 = self.a_f1.as_mut().unwrap();
        let p2 = self.a_f3_f2u.as_mut().unwrap();
        // fix p1, p2 on r pushed last round
        if round_in_phase != 1 {
            let r = if let Some(r) = self.v.get(round_in_phase - 2) {
                *r
            } else {
                return Err(crate::Error::InvalidOperationError(Some(
                    format!("Attempt to get message at round {} without pushing message at previous round. ", round_in_phase))));
            };
            Self::single_round_2mf_fix(p1, p2, self.dim, round_in_phase - 1, r);
        }
        let msg = Self::single_round_2pmf_sum(p1, p2, self.dim, round_in_phase);
        if round_in_phase == self.dim {
            // clean up cache
            self.a_f1 = None;
            self.a_f3_f2u = None;
        }

        self.messages.push(msg);
        Ok(())
    }

    /// general prover helper for `phase1_talk` and `phase2_talk`
    /// * `p1`,`p2`: bookkeeping table for the two MLExtension: of same length
    /// * `round_in_phase`: round in current phase
    /// * `r`: randomness
    fn single_round_2mf_fix(p1: &mut [F], p2: &mut [F], nv: usize, round_in_phase: usize, r: F) {
        for b in 0..(1 << (nv - round_in_phase)) {
            p1[b] = p1[b << 1] * (F::one() - r) + p1[(b << 1) + 1] * r;
            p2[b] = p2[b << 1] * (F::one() - r) + p2[(b << 1) + 1] * r;
        }
    }

    /// general prover helper for `phase1_talk` and `phase2_talk`
    /// * `p1`,`p2`: bookkeeping table for the two MLExtension: of same length
    /// * `round_in_phase`: round in current phase
    fn single_round_2pmf_sum(
        p1: &[F],
        p2: &[F],
        nv: usize,
        round_in_phase: usize,
    ) -> XZZPS19PMsg<F> {
        let mut sum_p1_p2 = (F::zero(), F::zero(), F::zero());
        let ts = [F::zero(), F::one(), F::one() + F::one()];
        for b in 0..(1 << (nv - round_in_phase)) {
            for (i, t) in ts.iter().enumerate() {
                let mut product = p1[b << 1] * (F::one() - (*t)) + p1[(b << 1) + 1] * (*t);
                product = product * (p2[b << 1] * (F::one() - (*t)) + p2[(b << 1) + 1] * (*t));
                match i {
                    0 => sum_p1_p2.0 += product,
                    1 => sum_p1_p2.1 += product,
                    _ => sum_p1_p2.2 += product,
                }
            }
        }
        XZZPS19PMsg(sum_p1_p2.0, sum_p1_p2.1, sum_p1_p2.2)
    }

    #[inline]
    /// get sum of the gkr
    pub(crate) fn get_sum(&self) -> F {
        self.sum
    }
}

impl<'a, F, S, D> Prover<'a, F> for XZZPS19Prover<'a, F, S, D>
where
    F: Field,
    S: SparseMLExtension<F>,
    D: MLExtension<F>,
{
    type SparseMLE = S;
    type DenseMLE = D;
    type GKRFunc = GKRAsLink<'a, F, S, D>;

    fn setup(gkr: &'a Self::GKRFunc, g: &[F]) -> Result<Self, Self::Error> {
        let dim = unwrap_safe!(gkr.get_l());
        if g.len() == 0 {
            return Err(Self::Error::InvalidArgumentError(Some(String::from(
                "g is empty",
            ))));
        }
        if g.len() != dim {
            return Err(Self::Error::InvalidArgumentError(Some(format!(
                "dim = {} but size of g = {}",
                dim,
                g.len()
            ))));
        }
        let mut ans = Self {
            f1: gkr.get_f1(),
            f2: gkr.get_f2(),
            f3: gkr.get_f3(),
            g: g.to_vec(),
            dim,
            a_hg: None,
            dp_g: None,
            dict_f1: None,
            f2_table: None,
            sum: F::default(),
            u: Vec::new(),
            v: Vec::new(),
            a_f1: None,
            a_f3_f2u: None,
            messages: Vec::new(),
        };
        unwrap_safe!(ans.initialize_phase_one());
        unwrap_safe!(ans.phase1_talk());
        Ok(ans)
    }
}

impl<F, S, D> Protocol for XZZPS19Prover<'_, F, S, D>
where
    F: Field,
    S: SparseMLExtension<F>,
    D: MLExtension<F>,
{
    type InboundMessage = XZZPS19VMsg<F>;
    type OutBoundMessage = XZZPS19PMsg<F>;
    type Error = crate::Error;

    #[inline]
    fn current_round(&self) -> Result<u32, Self::Error> {
        Ok(self.messages.len() as u32)
    }

    fn is_active(&self) -> bool {
        self.messages.len() < 2 * self.dim // some messages haven't been processed
    }

    fn get_message(&self, round: u32) -> Result<Self::OutBoundMessage, Self::Error> {
        let round = round as usize;
        let current_round = self.current_round().unwrap() as usize;
        assert_safe!(round > 0);
        if round > current_round {
            return Err(Self::Error::InvalidOperationError(Some(format!(
                "Current round is {}, request message of round {}",
                current_round, round
            ))));
        }
        Ok(self.messages[round - 1].clone())
    }

    fn push_message(&mut self, msg: &Self::InboundMessage) -> Result<(), Self::Error> {
        // if in phase 1
        if self.u.len() < self.dim {
            self.u.push(msg.x)
        } else {
            self.v.push(msg.x)
        }

        if self.current_round().unwrap() < self.dim as u32 {
            unwrap_safe!(self.phase1_talk());
        } else {
            unwrap_safe!(self.phase2_talk());
        }
        Ok(())
    }
}

/// precompute I(g,z) on {0,1}^dim
fn precompute<F: Field>(g: &[F]) -> Vec<F> {
    let dim = g.len();
    let mut dp = Vec::with_capacity(1 << dim);
    dp.resize(1 << dim, F::zero());
    dp[0] = F::one() - g[0];
    dp[1] = g[0];
    for i in 1..dim {
        let dp_prev = (&dp[0..(1 << i)]).to_vec();
        for b in 0..(1 << i) {
            dp[b] = dp_prev[b] * (F::one() - g[i]);
            dp[b + (1 << i)] = dp_prev[b] * g[i];
        }
    }

    dp
}

/// Split the binary argument (z,x,y) into three
fn three_split(arg: usize, dim: usize) -> (usize, usize, usize) {
    let z = arg & ((1 << dim) - 1);
    let x = (arg & (((1 << dim) - 1) << dim)) >> dim;
    let y = (arg & (((1 << dim) - 1) << (2 * dim))) >> (2 * dim);
    (z, x, y)
}

/// a_hg.len == f2.len == dim
fn sum_of_gkr<F: Field>(a_hg: &[F], f2: &[F]) -> F {
    let mut s = F::zero();
    for (a, b) in a_hg.iter().zip(f2) {
        s = s + *a * *b;
    }
    s
}
