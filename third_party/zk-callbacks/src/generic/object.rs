use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::{
    R1CSVar,
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    convert::ToConstraintFieldGadget,
    fields::fp::FpVar,
    select::CondSelectGadget,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::borrow::Borrow;

/// A nullifier type. Represents a nullifier (or serial number).
pub type Nul<F> = F;
/// Represents nullifiers in zero knowledge.
pub type NulVar<F> = FpVar<F>;
/// Provides commitment randomness.
pub type ComRand<F> = F;
/// Represents commitment randomness in zero knowledge.
pub type ComRandVar<F> = FpVar<F>;
/// A callback list hash chain.
pub type CBHash<F> = F;
/// A callback list hash chain in zero knowledge.
pub type CBHashVar<F> = FpVar<F>;
/// A time.
pub type Time<F> = F;
/// Time representation in zero knowledge.
pub type TimeVar<F> = FpVar<F>;
/// A commitment.
pub type Com<F> = F;
/// A commitment in zero knowledge.
pub type ComVar<F> = FpVar<F>;
/// A base type for serialization.
pub type Ser<F> = F;
/// The serialization type in zero knowledge.
pub type SerVar<F> = FpVar<F>;
/// A unique identification.
pub type Id<F> = F;
/// A unique ID in zero knowledge.
pub type IdVar<F> = FpVar<F>;

/// The ZKFields type provides all the necessary types for a user to properly interact with a
/// server. It is always contained within the `User` type.
#[derive(Clone, Default, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ZKFields<F: PrimeField> {
    /// The nullifier or serial number of the user state.
    pub nul: Nul<F>,
    /// The commitment randomness of the user.
    pub com_rand: ComRand<F>,
    /// The current callback list, as a hash chain.
    pub callback_hash: CBHash<F>,
    /// The new callback hash list, only used while ingesting is in progress.
    pub new_in_progress_callback_hash: CBHash<F>,
    /// The old callback hash list, only used while ingesting is in progress.
    pub old_in_progress_callback_hash: CBHash<F>,
    /// If the current ingestion is over, or is in progress.
    pub is_ingest_over: bool,
}

/// The ZKFieldsVar type provides the necessary types to interact with a server in zero knowledge.
#[derive(Clone, Debug)]
pub struct ZKFieldsVar<F: PrimeField> {
    /// The nullifier or serial number of the user state.
    pub nul: NulVar<F>,
    /// The commitment randomness of the user.
    pub com_rand: ComRandVar<F>,
    /// The current callback list, as a hash chain.
    pub callback_hash: CBHashVar<F>,
    /// The new callback hash list, only used while ingesting is in progress.
    pub new_in_progress_callback_hash: CBHashVar<F>,
    /// The old callback hash list, only used while ingesting is in progress.
    pub old_in_progress_callback_hash: CBHashVar<F>,
    /// If the current ingestion is over, or is in progress.
    pub is_ingest_over: Boolean<F>,
}

impl<F: PrimeField> ZKFields<F> {
    /// Serialize the bookkeeping fields into a vector of field elements.
    pub fn serialize(&self) -> Vec<Ser<F>> {
        [
            self.nul.to_field_elements().unwrap(),
            self.com_rand.to_field_elements().unwrap(),
            self.callback_hash.to_field_elements().unwrap(),
            self.new_in_progress_callback_hash
                .to_field_elements()
                .unwrap(),
            self.old_in_progress_callback_hash
                .to_field_elements()
                .unwrap(),
            self.is_ingest_over.to_field_elements().unwrap(),
        ]
        .concat()
    }
}

impl<F: PrimeField> ZKFieldsVar<F> {
    /// Serialize the bookkeeping fields in-circuit.
    pub fn serialize(&self) -> Result<Vec<SerVar<F>>, SynthesisError> {
        Ok([
            self.nul.to_constraint_field()?,
            self.com_rand.to_constraint_field()?,
            self.callback_hash.to_constraint_field()?,
            self.new_in_progress_callback_hash.to_constraint_field()?,
            self.old_in_progress_callback_hash.to_constraint_field()?,
            self.is_ingest_over.to_constraint_field()?,
        ]
        .concat())
    }
}

impl<F: PrimeField> R1CSVar<F> for ZKFieldsVar<F> {
    type Value = ZKFields<F>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.nul
            .cs()
            .or(self.com_rand.cs())
            .or(self.callback_hash.cs())
            .or(self.new_in_progress_callback_hash.cs())
            .or(self.old_in_progress_callback_hash.cs())
            .or(self.is_ingest_over.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(ZKFields {
            nul: self.nul.value()?,
            com_rand: self.com_rand.value()?,
            callback_hash: self.callback_hash.value()?,
            new_in_progress_callback_hash: self.new_in_progress_callback_hash.value()?,
            old_in_progress_callback_hash: self.old_in_progress_callback_hash.value()?,
            is_ingest_over: self.is_ingest_over.value()?,
        })
    }
}

impl<F: PrimeField> AllocVar<ZKFields<F>, F> for ZKFieldsVar<F> {
    fn new_variable<T: Borrow<ZKFields<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();
        res.and_then(|rec| {
            let rec = rec.borrow();
            let nul = NulVar::new_variable(ns!(cs, "nul"), || Ok(rec.nul), mode)?;
            let com_rand =
                ComRandVar::new_variable(ns!(cs, "com_rand"), || Ok(rec.com_rand), mode)?;
            let callback_hash =
                CBHashVar::new_variable(ns!(cs, "callback_hash"), || Ok(rec.callback_hash), mode)?;
            let new_in_progress_callback_hash = CBHashVar::new_variable(
                ns!(cs, "new_in_progress_callback_hash"),
                || Ok(rec.new_in_progress_callback_hash),
                mode,
            )?;
            let old_in_progress_callback_hash = CBHashVar::new_variable(
                ns!(cs, "old_in_progress_callback_hash"),
                || Ok(rec.old_in_progress_callback_hash),
                mode,
            )?;
            let is_ingest_over =
                Boolean::new_variable(ns!(cs, "is_ingest_over"), || Ok(rec.is_ingest_over), mode)?;
            Ok(ZKFieldsVar {
                nul,
                com_rand,
                callback_hash,
                new_in_progress_callback_hash,
                old_in_progress_callback_hash,
                is_ingest_over,
            })
        })
    }
}

impl<F: PrimeField> CondSelectGadget<F> for ZKFieldsVar<F> {
    fn conditionally_select(
        cond: &Boolean<F>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let nul = <NulVar<F>>::conditionally_select(cond, &true_value.nul, &false_value.nul)?;
        let com_rand = <ComRandVar<F>>::conditionally_select(
            cond,
            &true_value.com_rand,
            &false_value.com_rand,
        )?;
        let callback_hash = <CBHashVar<F> as CondSelectGadget<F>>::conditionally_select(
            cond,
            &true_value.callback_hash,
            &false_value.callback_hash,
        )?;
        let new_in_progress_callback_hash = <CBHashVar<F>>::conditionally_select(
            cond,
            &true_value.new_in_progress_callback_hash,
            &false_value.new_in_progress_callback_hash,
        )?;
        let old_in_progress_callback_hash = <CBHashVar<F>>::conditionally_select(
            cond,
            &true_value.old_in_progress_callback_hash,
            &false_value.old_in_progress_callback_hash,
        )?;
        let is_ingest_over = <Boolean<F>>::conditionally_select(
            cond,
            &true_value.is_ingest_over,
            &false_value.is_ingest_over,
        )?;

        Ok(Self {
            nul,
            com_rand,
            callback_hash,
            new_in_progress_callback_hash,
            old_in_progress_callback_hash,
            is_ingest_over,
        })
    }
}
