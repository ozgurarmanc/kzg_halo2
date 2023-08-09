use crate::kzg_variables::{polynomial::Polynomial, trusted_setup::trusted_setup_generator};
use halo2::arithmetic::Field;
use halo2::halo2curves::bn256::{Fr, G1Affine, G2Affine};
use halo2::halo2curves::group::Curve;
use halo2::halo2curves::pairing::PairingCurveAffine;

/// (K)ate (Z)averucha (G)oldberg Commitment Algorithm
///
/// (Be careful to pronounce Kate as Kahr-tey :]. https://www.cs.purdue.edu/homes/akate/howtopronounce.html)
pub fn kzg(polynomial: Polynomial, challenge: Fr) {
    // Constructing Structured Reference String that is suitable to the given polynomial
    let (srs_c1, srs_c2) = trusted_setup_generator(polynomial.coefficients.len());

    // Evaluating challenge and subtracting it from the constant value of the polynomial
    // Which will allow new polynomial to be perfect divided with the (x - challenge)
    let eval_of_challenge = polynomial.eval(&challenge);
    let mut numerator = polynomial.clone();
    numerator.coefficients[0] -= eval_of_challenge;
    let denominator = Polynomial::new(vec![challenge.neg(), Fr::ONE]);
    // Calculating Q(x) or aka quotient polynomial
    let quotient_polynomial = numerator.long_division(denominator);

    // [P(x)]_1 and [Q(x)]_1
    let polynomial_commitment = polynomial.commitment(&srs_c1);
    let quotient_commitment = quotient_polynomial.commitment(&srs_c1);

    // [s - challenge]_2
    // s is the secret that we don't know. Also, as known as toxic waste.
    let generator_g2 = G2Affine::generator();
    let challenge_g2 = generator_g2 * challenge;
    let s_sub_challenge = srs_c2[1] - challenge_g2;

    // Left pair (Pair one)
    // e([Q(x)]_1, [s - challenge]_2)
    let pair_1 = quotient_commitment.pairing_with(&s_sub_challenge.to_affine());

    // [eval_of_challenge]1
    let generator_g1 = G1Affine::generator();
    let eval_of_challenge_g1 = generator_g1 * eval_of_challenge;
    let polynomial_commitment_sub_y = polynomial_commitment - eval_of_challenge_g1;

    // Right pair (Pair two)
    // e([P(x)]_1 - [eval_of_challenge]_1, G2)
    let pair_2 = polynomial_commitment_sub_y
        .to_affine()
        .pairing_with(&generator_g2);

    // We calculated Q(x) as (P(x) - eval_of_challenge) / (x - challenge)
    // This assertion checks if:
    // [Q(s)]_1 * [s - challenge]_2 == [P(s) - eval_of_challenge]_1
    // Thanks to pairing we can use s without knowing it.
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
        // Test for the KZG algorithm
        let polynomial = Polynomial::random(123);
        let rng = &mut thread_rng();
        let challenge = Fr::random(rng);
        kzg(polynomial, challenge);
    }
}
