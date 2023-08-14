use halo2::{
    arithmetic::Field,
    halo2curves::{
        bn256::{Fr, G1Affine, G2Affine, G1, G2},
        ff::PrimeField,
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

// p(x)  =  4 * x^0 + 5 * x^1 + 6 * x^2
// coeff = [4, 5, 6]
// p(1)  =  4 * 1   + 5 * 1   + 6 * 1
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

    /// Adds two polynomials
    pub fn polynomial_addition(&self, rhs: Self) -> Self {
        let mut big = self.coefficients.clone().max(rhs.coefficients.clone());
        let small = self.coefficients.clone().min(rhs.coefficients.clone());
        for i in 0..small.len() {
            big[i] += small[i];
        }
        Polynomial::new(big)
    }

    /// Subtracts two polynomials
    pub fn polynomial_subtraction(&self, rhs: Self) -> Self {
        let mut big = self.coefficients.clone().max(rhs.coefficients.clone());
        let small = self.coefficients.clone().min(rhs.coefficients.clone());
        for i in 0..small.len() {
            big[i] -= small[i];
        }
        Polynomial::new(big)
    }

    /// Multiplies two polynomials
    pub fn polynomial_multiplication(&self, rhs: Self) -> Self {
        let mut result = vec![Fr::zero(); self.coefficients.len() + rhs.coefficients.len() - 1];
        for i in 0..self.coefficients.len() {
            for j in 0..rhs.coefficients.len() {
                result[i + j] += self.coefficients[i] * rhs.coefficients[j];
            }
        }
        Polynomial::new(result)
    }

    // p(x) = (x - 2)(x - 3) = roots are 2, 3
    // p(a) = 0, a = root of p
    // p(x) = 1*x^2 + 2*x^1 + 1*x^0
    // z = 5
    // p(z) = 1*25 + 2*5 + 1 = 36 = y
    // q(x) = (p(x) - y) / (x - z)
    //      = (1*x^2 + 2*x^1 + 1 - 36) / (x - 5)
    //      = (1*x^2 + 2*x^1 - 35) / (x - 5)
    //      = (x + 7)(x - 5) / (x - 5)
    //      = (x + 7)
    /// Calculates quotient using long division algorithm
    pub fn long_division(&self, rhs: Self) -> Self {
        // Here assigning it in reverse order and at the end of the function it will be reverted.
        let mut coefficients = self.coefficients.clone();
        coefficients.reverse();

        // Biggest degree of the quotient will always be the biggest degree's coefficient from
        // the numerator polynomial. That is why it is assigned here
        let mut quotient: Vec<Fr> = vec![coefficients[0]];

        // Long division algorithm
        for i in 0..coefficients.len() - 2 {
            quotient.push(coefficients[i + 1] - quotient[i] * rhs.coefficients[0]);
        }

        // Revert quotient to correct positioning for the whole algorithm
        quotient.reverse();

        Polynomial::new(quotient)
    }

    /// This function will build a polynomial from values and given domain.
    /// Will use lagrange interpolation.
    pub fn lagrange(values: Vec<Fr>, domain: Vec<Fr>) -> Self {
        let mut lagrange_polynomial = Polynomial::new(vec![Fr::ZERO]);
        for i in 0..values.len() {
            let mut mul_numerator = Polynomial::new(vec![Fr::ONE]);
            let mut mul_denominator = Fr::ONE;

            for j in 0..values.len() {
                if i == j {
                    continue;
                }
                let numerator =
                    Polynomial::new(vec![Fr::from_u128(j.try_into().unwrap()).neg(), Fr::ONE]);
                let denominator = domain[i] - domain[j];
                mul_numerator = mul_numerator.polynomial_multiplication(numerator.clone());
                mul_denominator *= denominator;
            }

            let numerator =
                mul_numerator.polynomial_multiplication(Polynomial::new(vec![mul_denominator
                    .invert()
                    .unwrap()]));

            let res = Polynomial::new(
                numerator
                    .coefficients
                    .iter()
                    .map(|x| x * values[i])
                    .collect(),
            );

            lagrange_polynomial = lagrange_polynomial.polynomial_addition(res);
        }
        lagrange_polynomial
    }

    /// Makes the commitment for the given polynomial and SRS
    pub fn commitment_g1(&self, srs_1: &Vec<G1Affine>) -> G1Affine {
        let mut commitment_c1 = G1::default();
        for i in 0..self.coefficients.len() {
            commitment_c1 += srs_1[i] * self.coefficients[i];
        }
        commitment_c1.to_affine()
    }

    /// Makes the commitment for the given polynomial and SRS
    pub fn commitment_g2(&self, srs_2: &Vec<G2Affine>) -> G2Affine {
        let mut commitment_c2 = G2::default();
        for i in 0..self.coefficients.len() {
            commitment_c2 += srs_2[i] * self.coefficients[i];
        }
        commitment_c2.to_affine()
    }
}
