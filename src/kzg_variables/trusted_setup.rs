use halo2::{
    arithmetic::Field,
    halo2curves::{
        bn256::{Fr, G1Affine, G2Affine},
        group::Curve,
    },
};
use rand::thread_rng;

pub fn trusted_setup_generator(length: usize) -> (Vec<G1Affine>, Vec<G2Affine>) {
    let generator_g1 = G1Affine::generator();
    let generator_g2 = G2Affine::generator();
    let rng = &mut thread_rng();
    let toxic_waste = Fr::random(rng);
    let mut trusted_setup_g1 = Vec::new();
    let mut trusted_setup_g2 = Vec::new();

    let mut toxic_waste_powers = Fr::ONE;
    for _ in 0..length {
        trusted_setup_g1.push((generator_g1 * toxic_waste_powers).to_affine());
        trusted_setup_g2.push((generator_g2 * toxic_waste_powers).to_affine());
        toxic_waste_powers *= toxic_waste;
    }

    (trusted_setup_g1, trusted_setup_g2)
}
