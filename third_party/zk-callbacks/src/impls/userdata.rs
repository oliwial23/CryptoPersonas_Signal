use crate::generic::user::UserData;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::{Fp, FpConfig, PrimeField, ToConstraintField};
use ark_r1cs_std::{
    boolean::Boolean,
    convert::{ToBytesGadget, ToConstraintFieldGadget},
    fields::fp::FpVar,
    uint128::UInt128,
    uint16::UInt16,
    uint32::UInt32,
    uint64::UInt64,
    uint8::UInt8,
};
use ark_relations::r1cs::SynthesisError;

macro_rules! impl_userdata_generic {
    ( $x:ty, $y:ty ) => {
        impl<G: PrimeField + Absorb> UserData<G> for $x {
            type UserDataVar = $y;

            fn serialize_elements(&self) -> Vec<crate::generic::object::Ser<G>> {
                let mut buf: Vec<G> = Vec::new();
                buf.extend_from_slice(&self.to_field_elements().unwrap());
                buf
            }

            fn serialize_in_zk(
                user_var: Self::UserDataVar,
            ) -> Result<Vec<crate::generic::object::SerVar<G>>, SynthesisError> {
                let mut buf: Vec<FpVar<G>> = Vec::new();
                buf.extend_from_slice(&user_var.to_constraint_field()?);
                Ok(buf)
            }
        }
    };
}

impl<P: FpConfig<N>, const N: usize> UserData<Fp<P, N>> for Fp<P, N> {
    type UserDataVar = FpVar<Self>;

    fn serialize_elements(&self) -> Vec<crate::generic::object::Ser<Self>> {
        let mut buf: Vec<Self> = Vec::new();
        buf.extend_from_slice(&self.to_field_elements().unwrap());
        buf
    }

    fn serialize_in_zk(
        user_var: Self::UserDataVar,
    ) -> Result<Vec<crate::generic::object::SerVar<Self>>, SynthesisError> {
        let mut buf: Vec<FpVar<Self>> = Vec::new();
        buf.extend_from_slice(&user_var.to_constraint_field()?);
        Ok(buf)
    }
}

impl_userdata_generic!(bool, Boolean<G>);

impl<G: PrimeField + Absorb> UserData<G> for u8 {
    type UserDataVar = UInt8<G>;

    fn serialize_elements(&self) -> Vec<crate::generic::object::Ser<G>> {
        let mut buf: Vec<G> = Vec::new();
        buf.extend_from_slice(&self.to_le_bytes().to_field_elements().unwrap());
        buf
    }

    fn serialize_in_zk(
        user_var: Self::UserDataVar,
    ) -> Result<Vec<crate::generic::object::SerVar<G>>, SynthesisError> {
        let mut buf: Vec<FpVar<G>> = Vec::new();
        let v = [user_var; 1];
        let bytevec = &v.to_bytes_le()?;
        let ser_vec = bytevec.to_constraint_field()?;
        buf.extend_from_slice(&ser_vec);
        Ok(buf)
    }
}

macro_rules! impl_complex_userdata_generic {
    ( $x:ty, $y:ty ) => {
        impl<G: PrimeField + Absorb> UserData<G> for $x {
            type UserDataVar = $y;

            fn serialize_elements(&self) -> Vec<crate::generic::object::Ser<G>> {
                let mut buf: Vec<G> = Vec::new();
                buf.extend_from_slice(&self.to_le_bytes().to_field_elements().unwrap());
                buf
            }

            fn serialize_in_zk(
                user_var: Self::UserDataVar,
            ) -> Result<Vec<crate::generic::object::SerVar<G>>, SynthesisError> {
                let mut buf: Vec<FpVar<G>> = Vec::new();
                let boolvec = &user_var.to_bytes_le();
                let ser_vec = boolvec
                    .into_iter()
                    .flat_map(|x| x.to_constraint_field())
                    .flatten()
                    .collect::<Vec<FpVar<G>>>();
                buf.extend_from_slice(&ser_vec);
                Ok(buf)
            }
        }
    };
}

impl_complex_userdata_generic!(u16, UInt16<G>);
impl_complex_userdata_generic!(u32, UInt32<G>);
impl_complex_userdata_generic!(u64, UInt64<G>);
impl_complex_userdata_generic!(u128, UInt128<G>);

impl<G: PrimeField + Absorb> UserData<G> for () {
    type UserDataVar = ();

    fn serialize_elements(&self) -> Vec<crate::generic::object::Ser<G>> {
        vec![]
    }

    fn serialize_in_zk(
        _user_var: Self::UserDataVar,
    ) -> Result<Vec<crate::generic::object::SerVar<G>>, SynthesisError> {
        Ok(vec![])
    }
}

impl<G: PrimeField + Absorb, T: UserData<G>, const N: usize> UserData<G> for [T; N] {
    type UserDataVar = [T::UserDataVar; N];

    fn serialize_elements(&self) -> Vec<crate::generic::object::Ser<G>> {
        self.iter()
            .take(N)
            .flat_map(|i| i.serialize_elements())
            .collect::<Vec<_>>()
    }

    fn serialize_in_zk(
        user_var: Self::UserDataVar,
    ) -> Result<Vec<crate::generic::object::SerVar<G>>, SynthesisError> {
        let mut buf = Vec::new();

        #[allow(clippy::needless_range_loop)]
        for i in 0..N {
            let out = T::serialize_in_zk(user_var[i].clone())?;
            buf.extend_from_slice(&out);
        }
        Ok(buf)
    }
}
