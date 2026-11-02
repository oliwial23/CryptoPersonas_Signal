use std::cmp::Ordering;

use crate::{
    crypto::hash::HasherZK,
    impls::{
        centralized::{
            crypto::{FakeSigPubkey, FakeSigPubkeyVar},
            ds::sig::Signature,
        },
        hash::Poseidon,
    },
};
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::{ns, r1cs::SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{distributions::Standard, prelude::Distribution, thread_rng};

use crate::impls::centralized::ds::sigstore::NonmembStore;

/// A signed range and time.
#[derive(Clone, Default, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SignedRange<F: PrimeField, S: Signature<F>> {
    /// A range [a, b).
    pub range: (F, F),
    /// The epoch or time.
    pub epoch: F,
    /// The signature on the epoch and range.
    pub sig: S::Sig,
}

impl<F: PrimeField, S: Signature<F>> SignedRange<F, S> {
    /// Returns if an element is within a signed range.
    pub fn is_in_range(&self, elem: F) -> bool {
        self.range.0 <= elem && elem < self.range.1
    }
}

/// The signed range and time in-circuit.
#[derive(Clone)]
pub struct SignedRangeVar<F: PrimeField, S: Signature<F>> {
    /// A range in-circuit.
    pub range: (FpVar<F>, FpVar<F>),
    /// The epoch in-circuit.
    pub epoch: FpVar<F>,
    /// The signature variable.
    pub sig: S::SigVar,
}

impl<F: PrimeField, S: Signature<F>> AllocVar<SignedRange<F, S>, F> for SignedRangeVar<F, S> {
    fn new_variable<T: std::borrow::Borrow<SignedRange<F, S>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();
        res.and_then(|rec| {
            let rec = rec.borrow();
            let r0 = <FpVar<F>>::new_variable(ns!(cs, "r0"), || Ok(rec.range.0), mode)?;
            let r1 = <FpVar<F>>::new_variable(ns!(cs, "r1"), || Ok(rec.range.1), mode)?;
            let epoch = <FpVar<F>>::new_variable(ns!(cs, "epoch"), || Ok(rec.epoch), mode)?;

            let sig = S::SigVar::new_variable(ns!(cs, "sig"), || Ok(rec.sig.clone()), mode)?;
            Ok(SignedRangeVar {
                range: (r0, r1),
                epoch,
                sig,
            })
        })
    }
}

/// This is a nonmembership store which uses signed ranges.
///
/// To prove nonmembership, tickets are ordered from `0` to `((p - 1) / 2) - 1`.
/// A nonmembership witness consists of a range [a, b) such that the ticket t lies within this
/// range.
///
/// On an epoch update, the new ranges are created and are resigned (along with the epoch).
/// Therefore, all signed ranges also contain an epoch.
#[derive(Clone, Default, Debug)]
pub struct SigRangeStore<F: PrimeField + Absorb, S: Signature<F>>
where
    Standard: Distribution<F>,
{
    privkey: S::Privkey,

    /// The public key for verifying signed ranges.
    pub pubkey: S::Pubkey,
    /// The list of nonmembership ranges.
    pub ncalled_cbs: Vec<SignedRange<F, S>>,

    /// The current epoch on this range store.
    pub epoch: F,
}

impl<F: PrimeField + Absorb, S: Signature<F>> SigRangeStore<F, S>
where
    Standard: Distribution<F>,
{
    /// Given an already existing database, initialize the store from this database (and epoch).
    pub fn from(privkey: S::Privkey, db: Vec<SignedRange<F, S>>, epoch: F) -> Self {
        let pubkey = S::get_pubkey(&privkey);
        Self {
            privkey,
            pubkey,
            ncalled_cbs: db,
            epoch,
        }
    }

    /// Get the signature public verification key for nonmembership.
    pub fn get_pubkey(&self) -> S::Pubkey {
        self.pubkey.clone()
    }

    /// Get the database of signed ranges.
    pub fn get_db(&self) -> Vec<SignedRange<F, S>> {
        self.ncalled_cbs.clone()
    }

    /// Rotate the key. Resigns all ranges with a new key.
    pub fn rotate_key(&mut self, new_key: S::Privkey) -> Result<(), ()> {
        self.pubkey = S::get_pubkey(&new_key);
        self.privkey = new_key;
        let mut sv: Vec<SignedRange<F, S>> = vec![];

        let mut rng = thread_rng();

        for range in &self.ncalled_cbs {
            let sig = S::sign(
                &self.privkey,
                &mut rng,
                <Poseidon<2>>::hash(&[range.range.0, range.range.1, range.epoch]),
            );
            match sig {
                Some(s) => {
                    sv.push(SignedRange {
                        range: (range.range.0, range.range.1),
                        epoch: range.epoch,
                        sig: s,
                    });
                }
                None => {
                    return Err(());
                }
            }
        }

        self.ncalled_cbs = sv;

        Ok(())
    }
}

impl<F: PrimeField + Absorb, S: Signature<F>> NonmembStore<F> for SigRangeStore<F, S>
where
    Standard: Distribution<F>,
    S: Default,
{
    type NonMembershipWitness = SignedRange<F, S>;

    type NonMembershipWitnessVar = SignedRangeVar<F, S>;

    type NonMembershipPub = S::Pubkey;

    type NonMembershipPubVar = S::PubkeyVar;

    fn new(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self {
        let sk = S::gen_key(rng);
        let init_range = (
            F::ZERO,
            F::from_bigint(F::MODULUS_MINUS_ONE_DIV_TWO).unwrap() - F::ONE,
        );
        let sig = S::sign(
            &sk,
            rng,
            <Poseidon<2>>::hash(&[init_range.0, init_range.1, F::ZERO]),
        )
        .unwrap();
        let first_range = SignedRange {
            range: init_range,
            epoch: F::ZERO,
            sig,
        };
        Self {
            privkey: sk.clone(),
            pubkey: S::get_pubkey(&sk),
            ncalled_cbs: vec![first_range],
            epoch: F::ZERO,
        }
    }

    fn get_epoch(&self) -> F {
        self.epoch
    }

    fn update_epoch(
        &mut self,
        rng: &mut (impl rand::CryptoRng + rand::RngCore),
        current_store: Vec<FakeSigPubkey<F>>,
    ) {
        self.epoch += F::ONE;

        let mut v = vec![];

        for i in &current_store {
            v.push(i.to());
        }

        v.sort();

        let mut updated_ranges = vec![];

        let mut bot = F::ZERO;

        for top in v {
            if bot != top {
                updated_ranges.push((bot, top));
            }
            bot = top + F::ONE;
        }

        // There's a small problem here: if we get a ticket at (top - 1), then there is exactly 1
        // left over at the top, in which case the range becomes [max, max). But then if someone
        // gets the max ticket, this check is not satisfied.
        if bot != F::ZERO {
            updated_ranges.push((
                bot,
                F::from_bigint(F::MODULUS_MINUS_ONE_DIV_TWO).unwrap() - F::ONE,
            ));
        }

        let mut sv = vec![];

        for range in updated_ranges {
            let sig = S::sign(
                &self.privkey,
                rng,
                <Poseidon<2>>::hash(&[range.0, range.1, self.epoch]),
            )
            .unwrap();
            sv.push(SignedRange {
                range,
                epoch: self.epoch,
                sig,
            });
        }

        if sv.is_empty() {
            let init_range = (
                F::ZERO,
                F::from_bigint(F::MODULUS_MINUS_ONE_DIV_TWO).unwrap() - F::ONE,
            );
            let sig = S::sign(
                &self.privkey,
                rng,
                <Poseidon<2>>::hash(&[init_range.0, init_range.1, self.epoch]),
            )
            .unwrap();
            let first_range = SignedRange {
                range: init_range,
                epoch: self.epoch,
                sig,
            };
            sv.push(first_range);
        }

        self.ncalled_cbs = sv;
    }

    fn get_nmemb(
        &self,
        tik: &FakeSigPubkey<F>,
    ) -> Option<(Self::NonMembershipPub, Self::NonMembershipWitness)> {
        for sr in &self.ncalled_cbs {
            if sr.range.0 <= tik.to() && tik.to() < sr.range.1 {
                return Some((self.get_pubkey(), sr.clone()));
            }
        }
        None
    }

    fn verify_not_in(&self, tik: FakeSigPubkey<F>) -> bool {
        for sr in &self.ncalled_cbs {
            if sr.range.0 <= tik.to() && tik.to() < sr.range.1 {
                return true;
            }
        }
        false
    }

    fn enforce_nonmembership_of(
        tikvar: FakeSigPubkeyVar<F>,
        extra_witness: Self::NonMembershipWitnessVar,
        extra_pub: Self::NonMembershipPubVar,
    ) -> Result<ark_r1cs_std::prelude::Boolean<F>, SynthesisError> {
        let c0 = tikvar
            .0
            .is_cmp_unchecked(&extra_witness.range.0, Ordering::Greater, true)?;
        let c1 = tikvar
            .0
            .is_cmp_unchecked(&extra_witness.range.1, Ordering::Less, false)?;

        let range_correct = c0 & c1;

        let c2 = S::verify_zk(
            extra_pub,
            extra_witness.sig,
            <Poseidon<2>>::hash_in_zk(&[
                extra_witness.range.0,
                extra_witness.range.1,
                extra_witness.epoch,
            ])?,
        )?;

        Ok(range_correct & c2)
    }

    fn get_nmemb_pub(&self) -> Self::NonMembershipPub {
        self.get_pubkey()
    }
}
