//! Randomization of big integers

use rand::Rng;
use rand::distributions::uniform::{SampleUniform, UniformSampler};

use BigInt;
use BigUint;
use Sign::*;

use big_digit::BigDigit;
use bigint::{magnitude, into_magnitude};

use traits::Zero;
use integer::Integer;

pub trait RandBigInt {
    /// Generate a random `BigUint` of the given bit size.
    fn gen_biguint(&mut self, bit_size: usize) -> BigUint;

    /// Generate a random BigInt of the given bit size.
    fn gen_bigint(&mut self, bit_size: usize) -> BigInt;

    /// Generate a random `BigUint` less than the given bound. Fails
    /// when the bound is zero.
    fn gen_biguint_below(&mut self, bound: &BigUint) -> BigUint;

    /// Generate a random `BigUint` within the given range. The lower
    /// bound is inclusive; the upper bound is exclusive. Fails when
    /// the upper bound is not greater than the lower bound.
    fn gen_biguint_range(&mut self, lbound: &BigUint, ubound: &BigUint) -> BigUint;

    /// Generate a random `BigInt` within the given range. The lower
    /// bound is inclusive; the upper bound is exclusive. Fails when
    /// the upper bound is not greater than the lower bound.
    fn gen_bigint_range(&mut self, lbound: &BigInt, ubound: &BigInt) -> BigInt;
}

impl<R: Rng + ?Sized> RandBigInt for R {
    fn gen_biguint(&mut self, bit_size: usize) -> BigUint {
        use super::big_digit::BITS;
        let (digits, rem) = bit_size.div_rem(&BITS);
        let mut data = Vec::with_capacity(digits + 1);
        for _ in 0..digits {
            data.push(self.gen());
        }
        if rem > 0 {
            let final_digit: BigDigit = self.gen();
            data.push(final_digit >> (BITS - rem));
        }
        BigUint::new(data)
    }

    fn gen_bigint(&mut self, bit_size: usize) -> BigInt {
        loop {
            // Generate a random BigUint...
            let biguint = self.gen_biguint(bit_size);
            // ...and then randomly assign it a Sign...
            let sign = if biguint.is_zero() {
                // ...except that if the BigUint is zero, we need to try
                // again with probability 0.5. This is because otherwise,
                // the probability of generating a zero BigInt would be
                // double that of any other number.
                if self.gen() {
                    continue;
                } else {
                    NoSign
                }
            } else if self.gen() {
                Plus
            } else {
                Minus
            };
            return BigInt::from_biguint(sign, biguint);
        }
    }

    fn gen_biguint_below(&mut self, bound: &BigUint) -> BigUint {
        assert!(!bound.is_zero());
        let bits = bound.bits();
        loop {
            let n = self.gen_biguint(bits);
            if n < *bound {
                return n;
            }
        }
    }

    fn gen_biguint_range(&mut self, lbound: &BigUint, ubound: &BigUint) -> BigUint {
        assert!(*lbound < *ubound);
        if lbound.is_zero() {
            self.gen_biguint_below(ubound)
        } else {
            lbound + self.gen_biguint_below(&(ubound - lbound))
        }
    }

    fn gen_bigint_range(&mut self, lbound: &BigInt, ubound: &BigInt) -> BigInt {
        assert!(*lbound < *ubound);
        if lbound.is_zero() {
            BigInt::from(self.gen_biguint_below(magnitude(&ubound)))
        } else if ubound.is_zero() {
            lbound + BigInt::from(self.gen_biguint_below(magnitude(&lbound)))
        } else {
            let delta = ubound - lbound;
            lbound + BigInt::from(self.gen_biguint_below(magnitude(&delta)))
        }
    }
}


/// The back-end implementing rand's `UniformSampler` for `BigUint`.
#[derive(Clone, Debug)]
pub struct UniformBigUint {
    base: BigUint,
    len: BigUint,
}

impl UniformSampler for UniformBigUint {
    type X = BigUint;

    fn new(low: Self::X, high: Self::X) -> Self {
        assert!(low < high);
        UniformBigUint {
            len: high - &low,
            base: low,
        }
    }

    fn new_inclusive(low: Self::X, high: Self::X) -> Self {
        assert!(low <= high);
        Self::new(low, high + 1u32)
    }

    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Self::X {
        &self.base + rng.gen_biguint_below(&self.len)
    }

    fn sample_single<R: Rng + ?Sized>(low: Self::X, high: Self::X, rng: &mut R) -> Self::X {
        rng.gen_biguint_range(&low, &high)
    }
}

impl SampleUniform for BigUint {
    type Sampler = UniformBigUint;
}


/// The back-end implementing rand's `UniformSampler` for `BigInt`.
#[derive(Clone, Debug)]
pub struct UniformBigInt {
    base: BigInt,
    len: BigUint,
}

impl UniformSampler for UniformBigInt {
    type X = BigInt;

    fn new(low: Self::X, high: Self::X) -> Self {
        assert!(low < high);
        UniformBigInt {
            len: into_magnitude(high - &low),
            base: low,
        }
    }

    fn new_inclusive(low: Self::X, high: Self::X) -> Self {
        assert!(low <= high);
        Self::new(low, high + 1u32)
    }

    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Self::X {
        &self.base + BigInt::from(rng.gen_biguint_below(&self.len))
    }

    fn sample_single<R: Rng + ?Sized>(low: Self::X, high: Self::X, rng: &mut R) -> Self::X {
        rng.gen_bigint_range(&low, &high)
    }
}

impl SampleUniform for BigInt {
    type Sampler = UniformBigInt;
}
