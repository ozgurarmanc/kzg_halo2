use std::ops::Sub;

use halo2::{
    arithmetic::Field,
    halo2curves::{
        bn256::{Fr, G2Affine},
        ff::PrimeField,
        group::Curve,
        pairing::PairingCurveAffine,
    },
};

use crate::{
    kzg::Proof,
    kzg_variables::{polynomial::Polynomial, trusted_setup::Params},
};

pub fn prove(vector: Vec<Fr>, challenge: Vec<Fr>, params: &Params) -> Proof {
    // Constructing vector polynomial with lagrange interpolation
    let polynomial = Polynomial::lagrange(
        vector.clone(),
        vec![
            Fr::from_u128(0),
            Fr::from_u128(1),
            Fr::from_u128(2),
            Fr::from_u128(3),
        ],
    );

    // Constructing challenge polynomial I(x)
    let challenge_polynomial = Polynomial::lagrange(vector, challenge.clone());
    let numerator = polynomial.polynomial_subtraction(challenge_polynomial);

    // Constructing zero polynomial Z(x)
    let mut zero_polynomial = Polynomial::new(vec![Fr::ONE]);
    for items in challenge.iter() {
        zero_polynomial =
            zero_polynomial.polynomial_multiplication(Polynomial::new(vec![-items, Fr::ONE]));
    }
    let denominator = zero_polynomial;
    // Calculating Q(x) or aka quotient polynomial
    let quotient_polynomial = numerator.long_division(denominator);

    // [P(x)]_1 and [Q(x)]_1
    let polynomial_commitment = polynomial.commitment_g1(&params.g1);
    let quotient_commitment = quotient_polynomial.commitment_g1(&params.g1);

    let eval_of_challenge = Fr::ZERO;
    Proof {
        polynomial_commitment,
        quotient_commitment,
        eval_of_challenge,
    }
}

/// Verification algorithm
pub fn verify(proof: Proof, vector: Vec<Fr>, challenge: Vec<Fr>, params: &Params) -> bool {
    let generator_g2 = G2Affine::generator();

    // Constructing challenge polynomial I(x)
    let challenge_polynomial = Polynomial::lagrange(vector, challenge.clone());
    let challenge_polynomial_commitment = challenge_polynomial.commitment_g1(&params.g1);

    // Constructing zero polynomial Z(x)
    let mut zero_polynomial = Polynomial::new(vec![Fr::ONE]);
    for items in challenge.iter() {
        zero_polynomial =
            zero_polynomial.polynomial_multiplication(Polynomial::new(vec![-items, Fr::ONE]));
    }
    let zero_polynomial_commitment = zero_polynomial.commitment_g2(&params.g2);

    // Left pair (Pair one)
    // e([Q(x)]_1, Z(x)_2)
    let pair_1 = proof
        .quotient_commitment
        .pairing_with(&zero_polynomial_commitment);

    // P(x)_1 - I(x)_1
    let polynomial_commitment_sub_challenge_commitment = proof
        .polynomial_commitment
        .sub(challenge_polynomial_commitment);

    // Right pair (Pair two)
    // e([P(x)]_1 - I(x)_1, G2)
    let pair_2 = polynomial_commitment_sub_challenge_commitment
        .to_affine()
        .pairing_with(&generator_g2);

    // We calculated Q(x) as (P(x) - I(x)) / Z(x)
    // This assertion checks if:
    // [Q(s)]_1 * Z(s)_2 == [P(s) - I(s)]_1
    // Thanks to pairing we can use s without knowing it.
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
        // Vector that is known to prover and verifier
        let vector = vec![
            Fr::ONE,
            Fr::ONE + Fr::ONE + Fr::ONE + Fr::ONE + Fr::ONE,
            Fr::ONE + Fr::ONE,
            Fr::ONE + Fr::ONE + Fr::ONE,
        ];

        // Creating vector indexes as challanges known by both prover and the verifier
        let challenge = vec![
            Fr::from_u128(0),
            Fr::from_u128(1),
            Fr::from_u128(2),
            Fr::from_u128(3),
        ];

        let proof = prove(vector.clone(), challenge.clone(), &params);
        let res = verify(proof, vector, challenge, &params);

        assert!(res);
    }
}
