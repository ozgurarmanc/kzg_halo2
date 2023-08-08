#![allow(non_snake_case)]

pub mod kzg_variables;

use halo2::halo2curves::{
    bn256::{Fq as BnBase, Fr as BnScalar},
    ff::{FromUniformBytes, PrimeField},
    secp256k1::{Fp as SecpBase, Fq as SecpScalar},
};
/// Extention to the traits provided by halo2
pub trait FieldExt: PrimeField + FromUniformBytes<64> {}
impl FieldExt for BnBase {}
impl FieldExt for BnScalar {}
impl FieldExt for SecpBase {}
impl FieldExt for SecpScalar {}
