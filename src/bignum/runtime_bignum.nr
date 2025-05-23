use super::params::BigNumParams;
use super::utils::map::map;

use super::fns::{
    constrained_ops::{
        add, assert_is_not_equal, conditional_select, derive_from_seed, div, eq, mul, neg, sub,
        udiv, udiv_mod, umod, validate_in_field, validate_in_range,
    },
    expressions::{__compute_quadratic_expression, evaluate_quadratic_expression},
    serialization::{from_be_bytes, to_le_bytes},
    unconstrained_ops::{
        __add, __batch_invert, __batch_invert_slice, __derive_from_seed, __div, __eq, __invmod,
        __is_zero, __mul, __neg, __pow, __sub, __tonelli_shanks_sqrt, __udiv_mod,
    },
};
use std::ops::{Add, Div, Mul, Neg, Sub};

pub struct RuntimeBigNum<let N: u32, let MOD_BITS: u32> {
    pub limbs: [Field; N],
    pub params: BigNumParams<N, MOD_BITS>,
}

impl<let N: u32, let MOD_BITS: u32> RuntimeBigNum<N, MOD_BITS> {}

// All functions prefixed `__` are unconstrained!
// They're not actually decorated as `unconstrained` because to return the `params` (as part of Self) from an `unconstrained` fn would cause range constraints. Instead, each `__` fn wraps a call to an unconstrained fn, so that the already-range-constrained `params` can be inserted into Self after the unconstrained call.
pub(crate) trait RuntimeBigNumTrait<let N: u32, let MOD_BITS: u32>: Neg + Add + Sub + Mul + Div + Eq {
    pub fn new(params: BigNumParams<N, MOD_BITS>) -> Self;
    pub fn one(params: BigNumParams<N, MOD_BITS>) -> Self;
    pub fn derive_from_seed<let SeedBytes: u32>(
        params: BigNumParams<N, MOD_BITS>,
        seed: [u8; SeedBytes],
    ) -> Self;
    pub fn __derive_from_seed<let SeedBytes: u32>(
        params: BigNumParams<N, MOD_BITS>,
        seed: [u8; SeedBytes],
    ) -> Self;
    pub fn from_slice(params: BigNumParams<N, MOD_BITS>, limbs: [Field]) -> Self;
    pub fn from_array(params: BigNumParams<N, MOD_BITS>, limbs: [Field; N]) -> Self;
    pub fn from_be_bytes<let NBytes: u32>(
        params: BigNumParams<N, MOD_BITS>,
        x: [u8; NBytes],
    ) -> Self;

    pub fn to_le_bytes<let NBytes: u32>(self) -> [u8; NBytes];

    pub fn modulus(self) -> Self;
    pub fn modulus_bits() -> u32;
    pub fn num_limbs() -> u32;
    // pub fn get(self) -> [Field];
    pub fn get_limbs(self) -> [Field; N];
    pub fn get_limb(self, idx: u32) -> Field;
    pub fn set_limb(&mut self, idx: u32, value: Field);

    unconstrained fn __eq(self, other: Self) -> bool;
    unconstrained fn __is_zero(self) -> bool;

    // unconstrained
    pub fn __neg(self) -> Self;
    // unconstrained
    pub fn __add(self, other: Self) -> Self;
    // unconstrained
    pub fn __sub(self, other: Self) -> Self;
    // unconstrained
    pub fn __mul(self, other: Self) -> Self;
    // unconstrained
    pub fn __div(self, other: Self) -> Self;
    // unconstrained
    pub fn __udiv_mod(self, divisor: Self) -> (Self, Self);
    // unconstrained
    pub fn __invmod(self) -> Self;
    // unconstrained
    pub fn __pow(self, exponent: Self) -> Self;

    // unconstrained
    pub fn __batch_invert<let M: u32>(x: [Self; M]) -> [Self; M];
    unconstrained fn __batch_invert_slice<let M: u32>(to_invert: [Self]) -> [Self];

    pub fn __tonelli_shanks_sqrt(self) -> std::option::Option<Self>;

    // unconstrained
    pub fn __compute_quadratic_expression<let LHS_N: u32, let RHS_N: u32, let NUM_PRODUCTS: u32, let ADD_N: u32>(
        params: BigNumParams<N, MOD_BITS>,
        lhs_terms: [[Self; LHS_N]; NUM_PRODUCTS],
        lhs_flags: [[bool; LHS_N]; NUM_PRODUCTS],
        rhs_terms: [[Self; RHS_N]; NUM_PRODUCTS],
        rhs_flags: [[bool; RHS_N]; NUM_PRODUCTS],
        linear_terms: [Self; ADD_N],
        linear_flags: [bool; ADD_N],
    ) -> (Self, Self);

    pub fn evaluate_quadratic_expression<let LHS_N: u32, let RHS_N: u32, let NUM_PRODUCTS: u32, let ADD_N: u32>(
        params: BigNumParams<N, MOD_BITS>,
        lhs_terms: [[Self; LHS_N]; NUM_PRODUCTS],
        lhs_flags: [[bool; LHS_N]; NUM_PRODUCTS],
        rhs_terms: [[Self; RHS_N]; NUM_PRODUCTS],
        rhs_flags: [[bool; RHS_N]; NUM_PRODUCTS],
        linear_terms: [Self; ADD_N],
        linear_flags: [bool; ADD_N],
    );

    pub fn eq(lhs: Self, rhs: Self) -> bool {
        lhs == rhs
    }
    pub fn assert_is_not_equal(self, other: Self);
    pub fn validate_in_field(self);
    pub fn validate_in_range(self);
    // pub fn validate_gt(self, lhs: Self, rhs: Self);

    pub fn udiv_mod(numerator: Self, divisor: Self) -> (Self, Self);
    pub fn udiv(numerator: Self, divisor: Self) -> Self;
    pub fn umod(numerator: Self, divisor: Self) -> Self;

    pub fn conditional_select(lhs: Self, rhs: Self, predicate: bool) -> Self;
}

impl<let N: u32, let MOD_BITS: u32> Neg for RuntimeBigNum<N, MOD_BITS> {
    fn neg(self) -> Self {
        let params = self.params;
        Self { limbs: neg::<_, MOD_BITS>(params, self.limbs), params }
    }
}

impl<let N: u32, let MOD_BITS: u32> RuntimeBigNumTrait<N, MOD_BITS> for RuntimeBigNum<N, MOD_BITS> {

    fn new(params: BigNumParams<N, MOD_BITS>) -> Self {
        let limbs: [Field; N] = [0; N];
        Self { limbs, params }
    }

    fn one(params: BigNumParams<N, MOD_BITS>) -> Self {
        let mut result = RuntimeBigNum::new(params);
        result.limbs[0] = 1;
        result
    }

    fn derive_from_seed<let SeedBytes: u32>(
        params: BigNumParams<N, MOD_BITS>,
        seed: [u8; SeedBytes],
    ) -> Self {
        let limbs = unsafe { derive_from_seed::<_, MOD_BITS, _>(params, seed) };
        Self { limbs, params }
    }

    // UNCONSTRAINED! (Hence `__` prefix).
    fn __derive_from_seed<let SeedBytes: u32>(
        params: BigNumParams<N, MOD_BITS>,
        seed: [u8; SeedBytes],
    ) -> Self {
        let limbs = unsafe { __derive_from_seed::<_, MOD_BITS, _>(params, seed) };
        Self { limbs, params }
    }

    fn from_slice(params: BigNumParams<N, MOD_BITS>, limbs: [Field]) -> Self {
        Self { limbs: limbs.as_array(), params }
    }

    fn from_array(params: BigNumParams<N, MOD_BITS>, limbs: [Field; N]) -> Self {
        Self { limbs, params }
    }

    fn from_be_bytes<let NBytes: u32>(params: BigNumParams<N, MOD_BITS>, x: [u8; NBytes]) -> Self {
        Self { limbs: from_be_bytes::<_, MOD_BITS, _>(x), params }
    }

    fn to_le_bytes<let NBytes: u32>(self) -> [u8; NBytes] {
        to_le_bytes::<_, MOD_BITS, _>(self.limbs)
    }

    fn modulus(self) -> Self {
        let params = self.params;
        Self { limbs: params.modulus, params }
    }

    fn modulus_bits() -> u32 {
        MOD_BITS
    }

    fn num_limbs() -> u32 {
        N
    }

    // fn get(self) -> [Field] {
    //     self.get_limbs()
    // }

    fn get_limbs(self) -> [Field; N] {
        self.limbs
    }

    fn get_limb(self, idx: u32) -> Field {
        self.limbs[idx]
    }

    fn set_limb(&mut self, idx: u32, value: Field) {
        self.limbs[idx] = value;
    }

    unconstrained fn __eq(self, other: Self) -> bool {
        assert(self.params == other.params);
        __eq(self.limbs, other.limbs)
    }

    unconstrained fn __is_zero(self) -> bool {
        __is_zero(self.limbs)
    }

    // UNCONSTRAINED! (Hence `__` prefix).
    fn __neg(self) -> Self {
        let params = self.params;
        let limbs = unsafe { __neg(params, self.limbs) };
        Self { params, limbs }
    }

    // UNCONSTRAINED! (Hence `__` prefix).
    fn __add(self, other: Self) -> Self {
        let params = self.params;
        assert(params == other.params);
        let limbs = unsafe { __add(params, self.limbs, other.limbs) };
        Self { params, limbs }
    }

    // UNCONSTRAINED! (Hence `__` prefix).
    fn __sub(self, other: Self) -> Self {
        let params = self.params;
        assert(params == other.params);
        let limbs = unsafe { __sub(params, self.limbs, other.limbs) };
        Self { params, limbs }
    }

    // UNCONSTRAINED! (Hence `__` prefix).
    fn __mul(self, other: Self) -> Self {
        let params = self.params;
        assert(params == other.params);
        let limbs = unsafe { __mul::<_, MOD_BITS>(params, self.limbs, other.limbs) };
        Self { params, limbs }
    }

    // UNCONSTRAINED! (Hence `__` prefix).
    fn __div(self, divisor: Self) -> Self {
        let params = self.params;
        assert(params == divisor.params);
        let limbs = unsafe { __div::<_, MOD_BITS>(params, self.limbs, divisor.limbs) };
        Self { params, limbs }
    }

    // UNCONSTRAINED! (Hence `__` prefix).
    fn __udiv_mod(self, divisor: Self) -> (Self, Self) {
        let params = self.params;
        assert(params == divisor.params);
        let (q, r) = unsafe { __udiv_mod(self.limbs, divisor.limbs) };
        (Self { limbs: q, params }, Self { limbs: r, params })
    }

    // UNCONSTRAINED! (Hence `__` prefix).
    fn __invmod(self) -> Self {
        let params = self.params;
        assert(params.has_multiplicative_inverse);
        let limbs = unsafe { __invmod::<_, MOD_BITS>(params, self.limbs) };
        Self { limbs, params }
    }

    // UNCONSTRAINED! (Hence `__` prefix).
    fn __pow(self, exponent: Self) -> Self {
        let params = self.params;
        assert(params == exponent.params);
        let limbs = unsafe { __pow::<_, MOD_BITS>(params, self.limbs, exponent.limbs) };
        Self { limbs, params }
    }

    // UNCONSTRAINED! (Hence `__` prefix).
    fn __batch_invert<let M: u32>(x: [Self; M]) -> [Self; M] {
        let params = x[0].params;
        assert(params.has_multiplicative_inverse);
        let all_limbs =
            unsafe { __batch_invert::<_, MOD_BITS, _>(params, x.map(|bn| Self::get_limbs(bn))) };
        all_limbs.map(|limbs| Self { limbs, params })
    }

    // Note: can't return a slice from this unconstrained to a constrained function.
    unconstrained fn __batch_invert_slice<let M: u32>(x: [Self]) -> [Self] {
        let params = x[0].params;
        assert(params.has_multiplicative_inverse);
        let all_limbs = unsafe {
            let inv_slice =
                __batch_invert_slice::<_, MOD_BITS>(params, x.map(|bn| Self::get_limbs(bn)));
            inv_slice.as_array()
        };
        all_limbs.map(|limbs| Self { limbs, params })
    }

    // UNCONSTRAINED! (Hence `__` prefix).
    fn __tonelli_shanks_sqrt(self) -> std::option::Option<Self> {
        let params = self.params;
        let maybe_limbs = unsafe { __tonelli_shanks_sqrt(params, self.limbs) };
        maybe_limbs.map(|limbs| Self { limbs, params })
    }

    // UNCONSTRAINED! (Hence `__` prefix).
    fn __compute_quadratic_expression<let LHS_N: u32, let RHS_N: u32, let NUM_PRODUCTS: u32, let ADD_N: u32>(
        params: BigNumParams<N, MOD_BITS>,
        lhs_terms: [[Self; LHS_N]; NUM_PRODUCTS],
        lhs_flags: [[bool; LHS_N]; NUM_PRODUCTS],
        rhs_terms: [[Self; RHS_N]; NUM_PRODUCTS],
        rhs_flags: [[bool; RHS_N]; NUM_PRODUCTS],
        linear_terms: [Self; ADD_N],
        linear_flags: [bool; ADD_N],
    ) -> (Self, Self) {
        let (q_limbs, r_limbs) = unsafe {
            __compute_quadratic_expression::<_, MOD_BITS, _, _, _, _>(
                params,
                map(lhs_terms, |bns| map(bns, |bn| Self::get_limbs(bn))),
                lhs_flags,
                map(rhs_terms, |bns| map(bns, |bn| Self::get_limbs(bn))),
                rhs_flags,
                map(linear_terms, |bn| Self::get_limbs(bn)),
                linear_flags,
            )
        };
        (Self { limbs: q_limbs, params }, Self { limbs: r_limbs, params })
    }

    fn evaluate_quadratic_expression<let LHS_N: u32, let RHS_N: u32, let NUM_PRODUCTS: u32, let ADD_N: u32>(
        params: BigNumParams<N, MOD_BITS>,
        lhs_terms: [[Self; LHS_N]; NUM_PRODUCTS],
        lhs_flags: [[bool; LHS_N]; NUM_PRODUCTS],
        rhs_terms: [[Self; RHS_N]; NUM_PRODUCTS],
        rhs_flags: [[bool; RHS_N]; NUM_PRODUCTS],
        linear_terms: [Self; ADD_N],
        linear_flags: [bool; ADD_N],
    ) {
        evaluate_quadratic_expression::<_, MOD_BITS, _, _, _, _>(
            params,
            map(lhs_terms, |bns| map(bns, |bn| Self::get_limbs(bn))),
            lhs_flags,
            map(rhs_terms, |bns| map(bns, |bn| Self::get_limbs(bn))),
            rhs_flags,
            map(linear_terms, |bn| Self::get_limbs(bn)),
            linear_flags,
        )
    }

    fn validate_in_field(self: Self) {
        let params = self.params;
        validate_in_field::<_, MOD_BITS>(params, self.limbs);
    }

    fn validate_in_range(self) {
        validate_in_range::<_, MOD_BITS>(self.limbs);
    }

    fn assert_is_not_equal(self, other: Self) {
        let params = self.params;
        assert(params == other.params);
        assert_is_not_equal(params, self.limbs, other.limbs);
    }

    fn udiv_mod(self, divisor: Self) -> (Self, Self) {
        let params = self.params;
        assert(params == divisor.params);
        let (q, r) = udiv_mod::<_, MOD_BITS>(params, self.limbs, divisor.limbs);
        (Self { limbs: q, params }, Self { limbs: r, params })
    }

    fn udiv(self, divisor: Self) -> Self {
        let params = self.params;
        assert(params == divisor.params);
        Self { limbs: udiv::<_, MOD_BITS>(params, self.limbs, divisor.limbs), params }
    }

    fn umod(self, divisor: Self) -> Self {
        let params = self.params;
        assert(params == divisor.params);
        Self { limbs: umod::<_, MOD_BITS>(params, self.limbs, divisor.limbs), params }
    }

    fn conditional_select(lhs: Self, rhs: Self, predicate: bool) -> Self {
        let params = lhs.params;
        assert(params == rhs.params);
        Self { limbs: conditional_select(lhs.limbs, rhs.limbs, predicate), params }
    }
}

impl<let N: u32, let MOD_BITS: u32> std::ops::Add for RuntimeBigNum<N, MOD_BITS> {
    // Note: this method is expensive! Try to craft quadratic relations and directly evaluate them
    //       via evaluate_quadratic_expression
    fn add(self, other: Self) -> Self {
        let params = self.params;
        assert(params == other.params);
        Self { limbs: add::<_, MOD_BITS>(params, self.limbs, other.limbs), params }
    }
}

impl<let N: u32, let MOD_BITS: u32> std::ops::Sub for RuntimeBigNum<N, MOD_BITS> {
    // Note: this method is expensive! Try to craft quadratic relations and directly evaluate them
    //       via evaluate_quadratic_expression
    fn sub(self, other: Self) -> Self {
        let params = self.params;
        assert(params == other.params);
        Self { limbs: sub::<_, MOD_BITS>(params, self.limbs, other.limbs), params }
    }
}

impl<let N: u32, let MOD_BITS: u32> std::ops::Mul for RuntimeBigNum<N, MOD_BITS> {
    // Note: this method is expensive! Try to craft quadratic relations and directly evaluate them
    //       via evaluate_quadratic_expression
    // e.g. performing a sum of multiple multiplications and additions via `evaluate_quadratic_expression`
    //      will create much fewer constraints than calling `mul` and `add` directly
    fn mul(self, other: Self) -> Self {
        let params = self.params;
        assert(params == other.params);
        Self { limbs: mul::<_, MOD_BITS>(params, self.limbs, other.limbs), params }
    }
}

impl<let N: u32, let MOD_BITS: u32> std::ops::Div for RuntimeBigNum<N, MOD_BITS> {
    // Note: this method is expensive! Witness computation is extremely expensive as it requires modular exponentiation
    fn div(self, divisor: Self) -> Self {
        let params = self.params;
        assert(params == divisor.params);
        Self { limbs: div::<_, MOD_BITS>(params, self.limbs, divisor.limbs), params }
    }
}

impl<let N: u32, let MOD_BITS: u32> std::cmp::Eq for RuntimeBigNum<N, MOD_BITS> {
    fn eq(self, other: Self) -> bool {
        let params = self.params;
        assert(params == other.params);
        eq::<_, MOD_BITS>(params, self.limbs, other.limbs)
    }
}
