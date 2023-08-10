use halo2::{
    arithmetic::Field,
    halo2curves::{
        bn256::{Fr, G1Affine, G2Affine},
        group::Curve,
    },
};
use rand::thread_rng;

pub struct Params {
    pub g1: Vec<G1Affine>,
    pub g2: Vec<G2Affine>,
}

/// Builds SRS for the algorithm.
pub fn trusted_setup_generator(length: usize) -> Params {
    let generator_g1 = G1Affine::generator();
    let generator_g2 = G2Affine::generator();
    let rng = &mut thread_rng();
    // This toxic waste is the value that we create SRS by using it.
    // In real life implementations, programmers uses a SRS that is created
    // from a ceremony. Everyone can attend and give their random value and if
    // only one person destroys their toxic waste, all of the SRS will be safe to use.
    let toxic_waste = Fr::random(rng);
    let mut trusted_setup_g1 = Vec::new();
    let mut trusted_setup_g2 = Vec::new();

    // x = toxic_waste
    // SRS_g1 = g1 * x^0, g1 * x^1, g1 * x^2, g1 * x^3
    // SRS_g2 = g2 * x^0, g2 * x^1, g2 * x^2, g2 * x^3
    let mut toxic_waste_powers = Fr::ONE;
    for _ in 0..length {
        trusted_setup_g1.push((generator_g1 * toxic_waste_powers).to_affine());
        trusted_setup_g2.push((generator_g2 * toxic_waste_powers).to_affine());
        toxic_waste_powers *= toxic_waste;
    }

    Params {
        g1: trusted_setup_g1,
        g2: trusted_setup_g2,
    }
}
