use halo2::{
    arithmetic::Field,
    halo2curves::{
        bn256::{Fr, G1Affine, G1},
        group::Curve,
    },
};
use rand::thread_rng;
use std::ops::{AddAssign, Mul};

#[derive(Clone)]
pub struct Polynomial {
    pub(crate) coefficients: Vec<Fr>,
}

impl Polynomial {
    pub fn new(coefficients: Vec<Fr>) -> Self {
        Self { coefficients }
    }

    pub fn random(length: usize) -> Self {
        let mut random_polynomial_coeff = Vec::new();
        let rng = &mut thread_rng();
        for _ in 0..length {
            random_polynomial_coeff.push(Fr::random(rng.clone()));
        }
        Self {
            coefficients: random_polynomial_coeff,
        }
    }

    pub fn eval(&self, x: &Fr) -> Fr {
        let mut eval = Fr::ZERO;
        let mut point = Fr::ONE;
        for i in 0..self.coefficients.len() {
            eval += self.coefficients[i] * point;
            point *= x;
        }
        eval
    }

    pub fn quotient_calculator_for_kzg(&self, rhs: Self) -> Self {
        // Will divide lhs to rhs with perfect division operation.
        // If it is not a perfect division and rhs == degree 1, won't work.
        assert!(rhs.coefficients.len() == 2);
        // Biggest degree of the quotient will carry same coefficient from the self
        // Here assigning it in reverse order and at the end of the program we will make it correct
        let mut coefficients = self.coefficients.clone();
        coefficients.reverse();
        let mut quotient: Vec<Fr> = vec![coefficients[0]];

        // Long division algorithm for degree == 1 divisor
        for i in 0..coefficients.len() - 2 {
            quotient.push(coefficients[i + 1] - quotient[i] * rhs.coefficients[1]);
        }
        quotient.reverse();

        Polynomial::new(quotient)
    }

    pub fn commitment(&self, srs_1: &Vec<G1Affine>) -> G1Affine {
        let mut commitment_c1 = G1::default();

        for i in 0..self.coefficients.len() {
            commitment_c1.add_assign(srs_1[i].mul(self.coefficients[i]));
        }
        commitment_c1.to_affine()
    }
}
