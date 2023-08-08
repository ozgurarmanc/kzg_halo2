use halo2::{
    arithmetic::Field,
    halo2curves::{
        bn256::{Fr, G1Affine, G1},
        group::Curve,
    },
};
use rand::thread_rng;

/// Polynomial Structure
#[derive(Clone, Debug)]
pub struct Polynomial {
    // Coefficients of the polynomial
    pub(crate) coefficients: Vec<Fr>,
}

impl Polynomial {
    /// Creates a new polynomial from given vector
    pub fn new(coefficients: Vec<Fr>) -> Self {
        Self { coefficients }
    }

    /// Creates a new random polynomial with given length
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

    /// Evaluates polynomial on the given value
    pub fn eval(&self, x: &Fr) -> Fr {
        let mut eval = Fr::ZERO;
        let mut point = Fr::ONE;
        for i in 0..self.coefficients.len() {
            eval += self.coefficients[i] * point;
            point *= x;
        }
        eval
    }

    /// Calculates quotient using long division algorithm
    pub fn long_division(&self, rhs: Self) -> Self {
        // Will divide lhs to rhs with long division operation (Only divides perfect divisions).
        // Checks if rhs == degree 1 polynomial.
        assert!(rhs.coefficients.len() == 2);

        // Here assigning it in reverse order and at the end of the function it will be reverted.
        let mut coefficients = self.coefficients.clone();
        coefficients.reverse();

        // Biggest degree of the quotient will always be the biggest degree's coefficient from
        // the numerator polynomial. That is why it is assigned here
        let mut quotient: Vec<Fr> = vec![coefficients[0]];

        // Long division algorithm for degree == 1 divisor
        for i in 0..coefficients.len() - 2 {
            quotient.push(coefficients[i + 1] - quotient[i] * rhs.coefficients[0]);
        }

        // Revert quotient to correct positioning for the whole algorithm
        quotient.reverse();

        Polynomial::new(quotient)
    }

    /// Makes the commitment for the given polynomial
    pub fn commitment(&self, srs_1: &Vec<G1Affine>) -> G1Affine {
        let mut commitment_c1 = G1::default();
        for i in 0..self.coefficients.len() {
            commitment_c1 += srs_1[i] * self.coefficients[i];
        }
        commitment_c1.to_affine()
    }
}
