use crate::kzg_variables::{polynomial::Polynomial, trusted_setup::trusted_setup_generator};
use halo2::arithmetic::Field;
use halo2::halo2curves::bn256::{Fr, G1Affine, G2Affine};
use halo2::halo2curves::group::Curve;
use halo2::halo2curves::pairing::PairingCurveAffine;

pub fn kzg(polynomial: Polynomial, challenge: Fr) {
    // Constructing SRS that fits to our polynomial
    let (srs_c1, srs_c2) = trusted_setup_generator(polynomial.coefficients.len());

    // Evaluating challenge and subtracting it from the constant value of the polynomial
    let eval_of_challenge = polynomial.eval(&challenge);
    let mut numerator = polynomial.clone();
    numerator.coefficients[0] -= eval_of_challenge;
    // Calculating Q(x)
    let denominator = Polynomial::new(vec![challenge.neg(), Fr::ONE]);
    let quotient_polynomial = numerator.quotient_calculator_for_kzg(denominator);

    // [P(x)]1 and [Q(x)]1
    let polynomial_commitment = polynomial.commitment(&srs_c1);
    let quotient_commitment = quotient_polynomial.commitment(&srs_c1);

    // [s - z]2
    let generator_g2 = G2Affine::generator();
    let challenge_g2 = generator_g2 * challenge;
    let s_sub_z = srs_c2[1] - challenge_g2;
    let pair_1 = quotient_commitment.pairing_with(&s_sub_z.to_affine());

    // [y]1
    let generator_g1 = G1Affine::generator();
    let eval_of_challenge_g1 = generator_g1 * eval_of_challenge;
    let polynomial_commitment_sub_y = polynomial_commitment - eval_of_challenge_g1;
    let pair_2 = polynomial_commitment_sub_y
        .to_affine()
        .pairing_with(&generator_g2);

    assert_eq!(pair_1, pair_2);
}

#[cfg(test)]
mod tests {
    use super::kzg;
    use crate::kzg_variables::polynomial::Polynomial;
    use halo2::{arithmetic::Field, halo2curves::bn256::Fr};
    use rand::thread_rng;

    #[test]
    fn kzg_test() {
        let polynomial = Polynomial::random(123);
        let rng = &mut thread_rng();
        let challenge = Fr::random(rng);
        kzg(polynomial, challenge);
    }
}
