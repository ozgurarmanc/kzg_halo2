use crate::FieldExt;
use halo2::halo2curves::CurveAffine;
use rand::thread_rng;
use std::{
    marker::PhantomData,
    ops::{AddAssign, Mul},
};

struct Polynomial<C1: CurveAffine, C2: CurveAffine, F: FieldExt> {
    coefficients: Vec<F>,
    _p: PhantomData<(C1, C2)>,
}

impl<
        C1: CurveAffine + Mul<F, Output = C1> + AddAssign,
        C2: CurveAffine + Mul<F, Output = C2> + AddAssign,
        F: FieldExt,
    > Polynomial<C1, C2, F>
{
    fn new(coefficients: Vec<F>) -> Self {
        Self {
            coefficients,
            _p: PhantomData,
        }
    }

    fn random(length: usize) -> Vec<F> {
        let mut random_polynomial = Vec::new();
        let rng = &mut thread_rng();
        for _ in 0..length {
            random_polynomial.push(F::random(rng.clone()));
        }
        random_polynomial
    }

    fn eval(self, x: F) -> F {
        let mut eval = F::ZERO;
        let mut point = F::ONE;
        for i in 0..self.coefficients.len() {
            eval += self.coefficients[i] * point;
            point *= x;
        }
        eval
    }

    fn quotient_calculator_for_kzg(self, rhs: Self) -> Self {
        // Will divide lhs to rhs with perfect division operation.
        // If it is not a perfect division and rhs == degree 1, won't work.
        assert!(rhs.coefficients.len() == 2);
        // Biggest degree of the quotient will carry same coefficient from the self
        // Here assigning it in reverse order and at the end of the program we will make it correct
        let mut coefficients = self.coefficients.clone();
        coefficients.reverse();
        let mut quotient: Vec<F> = vec![coefficients[0]];

        // Long division algorithm for degree == 1 divisor
        for i in 0..coefficients.len() - 2 {
            quotient.push(coefficients[i + 1] - quotient[i] * rhs.coefficients[1]);
        }
        quotient.reverse();

        Polynomial::new(quotient)
    }

    fn commitment(self, srs_g1: Vec<C1>, srs_g2: Vec<C2>) -> (C1, C2) {
        let mut commitment_c1 = C1::default();
        let mut commitment_c2 = C2::default();

        for i in 0..self.coefficients.len() {
            commitment_c1.add_assign(srs_g1[i].mul(self.coefficients[i]));
            commitment_c2.add_assign(srs_g2[i].mul(self.coefficients[i]));
        }
        (commitment_c1, commitment_c2)
    }
}
