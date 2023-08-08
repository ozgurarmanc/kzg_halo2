use crate::FieldExt;
use halo2::halo2curves::CurveAffine;
use rand::thread_rng;
use std::ops::Mul;

pub fn trusted_setup_generator<
    C1: CurveAffine + Mul<F, Output = C1>,
    C2: CurveAffine + Mul<F, Output = C2>,
    F: FieldExt,
>(
    length: usize,
) -> (Vec<C1>, Vec<C2>) {
    let generator_g1 = C1::generator();
    let generator_g2 = C2::generator();
    let rng = &mut thread_rng();
    let toxic_waste = F::random(rng);
    let mut trusted_setup_g1 = Vec::new();
    let mut trusted_setup_g2 = Vec::new();

    let mut toxic_waste_powers = F::ONE;
    for _ in 0..length {
        trusted_setup_g1.push(generator_g1.mul(toxic_waste_powers));
        trusted_setup_g2.push(generator_g2.mul(toxic_waste_powers));

        toxic_waste_powers.mul_assign(toxic_waste);
    }

    (trusted_setup_g1, trusted_setup_g2)
}
