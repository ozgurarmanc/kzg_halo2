use halo2::{
    arithmetic::Field,
    halo2curves::{
        bn256::{Fr, G1Affine, G2Affine},
        group::Curve,
        pairing::PairingCurveAffine,
    },
};

use crate::{
    kzg::Proof,
    kzg_variables::{polynomial::Polynomial, trusted_setup::Params},
};

pub fn prove(vector: Vec<Fr>, challenge: Fr, params: &Params) -> Proof {
    let polynomial = Polynomial::lagrange(vector);
    // Evaluating challenge and subtracting it from the constant value of the polynomial
    // Which will allow new polynomial to be perfect divided with the (x - challenge)
    let eval_of_challenge = polynomial.eval(&challenge);
    let mut numerator = polynomial.clone();
    numerator.coefficients[0] -= eval_of_challenge;
    let denominator = Polynomial::new(vec![challenge.neg(), Fr::ONE]);
    // Calculating Q(x) or aka quotient polynomial
    let quotient_polynomial = numerator.long_division(denominator);

    // [P(x)]_1 and [Q(x)]_1
    let polynomial_commitment = polynomial.commitment(&params.g1);
    let quotient_commitment = quotient_polynomial.commitment(&params.g1);

    Proof {
        polynomial_commitment,
        quotient_commitment,
        eval_of_challenge,
    }
}

/// Verification algorithm
pub fn verify(proof: Proof, challenge: Fr, params: &Params) -> bool {
    // [s - challenge]_2
    // s is the secret that we don't know. Also, as known as toxic waste.
    let generator_g2 = G2Affine::generator();
    let challenge_g2 = generator_g2 * challenge;
    let s_sub_challenge = params.g2[1] - challenge_g2;

    // Left pair (Pair one)
    // e([Q(x)]_1, [s - challenge]_2)
    let pair_1 = proof
        .quotient_commitment
        .pairing_with(&s_sub_challenge.to_affine());

    // [eval_of_challenge]1
    let generator_g1 = G1Affine::generator();
    let eval_of_challenge_g1 = generator_g1 * proof.eval_of_challenge;
    let polynomial_commitment_sub_y = proof.polynomial_commitment - eval_of_challenge_g1;

    // Right pair (Pair two)
    // e([P(x)]_1 - [eval_of_challenge]_1, G2)
    let pair_2 = polynomial_commitment_sub_y
        .to_affine()
        .pairing_with(&generator_g2);

    // We calculated Q(x) as (P(x) - eval_of_challenge) / (x - challenge)
    // This assertion checks if:
    // [Q(s)]_1 * [s - challenge]_2 == [P(s) - eval_of_challenge]_1
    // Thanks to pairing we can use s without knowing it.
    // After here verifier satisfies that eval_of_challenge is constructed from given challenge as index.
    // That means prover has the vector and that index returns the value from the vector.
    pair_1 == pair_2
}

#[cfg(test)]
mod tests {
    use crate::{
        kzg_variables::trusted_setup::trusted_setup_generator,
        kzg_vector::{prove, verify},
    };
    use halo2::{
        arithmetic::Field,
        halo2curves::{bn256::Fr, ff::PrimeField},
    };

    #[test]
    fn kzg_vector_test() {
        // Constructing Structured Reference String that is suitable to the given polynomial
        let k = 123;
        let params = trusted_setup_generator(k);
        // Vector
        let vector = vec![
            Fr::ONE,
            Fr::ONE + Fr::ONE + Fr::ONE + Fr::ONE + Fr::ONE,
            Fr::ONE + Fr::ONE,
            Fr::ONE + Fr::ONE + Fr::ONE,
        ];

        // Generating challange known by both prover and the verifier
        let challenge = Fr::from_u128(0);

        let proof = prove(vector, challenge, &params);
        let res = verify(proof, challenge, &params);

        assert!(res);
    }
}
