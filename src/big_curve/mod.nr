pub(crate) mod scalar_field;
pub(crate) mod curve_jac;
pub(crate) mod utils;
pub mod curves;

use crate::bignum::BigNum;
use crate::bignum::BigNumTrait;

use super::big_curve::scalar_field::ScalarField;
use super::big_curve::curve_jac::AffineTranscript;
use super::big_curve::curve_jac::CurveJ;
use super::big_curve::utils::hash_to_curve::hash_to_curve;

use dep::sort::sort_advanced;

fn __sort_field_as_u32(lhs: Field, rhs: Field) -> bool {
    lhs as u32 < rhs as u32
}

fn assert_sorted(lhs: Field, rhs: Field) {
    let result = (rhs - lhs - 1);
    result.assert_max_bit_size::<32>();
}

struct SparseLookup<let N: u32> {
    keys: [Field; N],
    values: [Field; N],
    maximum: Field, // can be up to 2^32
}

/**
 * @brief records data used to reason about whether a key exists in a json blob
 **/
struct KeySearchResult {
    found: bool, // does the key exist?
    target_lt_smallest_entry: bool, // is the target keyhash smaller than the smallest keyhash in self.key_hashes?
    target_gt_largest_entry: bool, // is the target keyhash larger than the largest keyhash in self.key_hashes?
    lhs_index: Field, // either the index of the key being searched for, or the index of the keyhash in self.key_hashes that is closest to keyhash (hash > lhs_index_hash)
    rhs_index: Field, // either the index of the key being searched for, or the index of the keyhash in self.key_hashes that is closest to keyhash (hash < rhs_index_hash)
}

impl<let N: u32> SparseLookup<N> {
    fn create(_keys: [Field; N], _values: [Field; N], _maximum: Field) -> Self {
        let mut r: Self = SparseLookup { keys: [0; N], values: [0; N], maximum: _maximum };
        let sorted_keys = sort_advanced(_keys, __sort_field_as_u32, assert_sorted);
        r.keys = sorted_keys.sorted;
        for i in 0..N {
            r.values[i] = _values[sorted_keys.sort_indices[i]];
        }
        _maximum.assert_max_bit_size::<32>();
        r
    }

    unconstrained fn search_for_key_in_map(self, target: Field) -> KeySearchResult {
        let mut found_index: Field = 0;
        let mut found: bool = false;

        let mut lhs_maximum: Field = 0;
        let mut rhs_minimum: Field = -1;
        let mut lhs_maximum_index: Field = 0;
        let mut rhs_minimum_index: Field = 0;
        for i in 0..N {
            let key = self.keys[i];
            if (key == target) {
                found_index = i as Field;
                found = true;
                break;
            } else {
                if key.lt(target) & (lhs_maximum.lt(key)) {
                    lhs_maximum = key;
                    lhs_maximum_index = i as Field;
                }
                if (target.lt(key)) & (key.lt(rhs_minimum)) {
                    rhs_minimum = key;
                    rhs_minimum_index = i as Field;
                }
            }
        }
        let target_lt_smallest_entry = target.lt(self.keys[0]);
        let target_gt_largest_entry = self.keys[N - 1].lt(target);

        let result_not_first_or_last =
            !target_lt_smallest_entry & !target_gt_largest_entry & !found;

        let mut lhs_index = result_not_first_or_last as Field * lhs_maximum_index;
        let mut rhs_index = result_not_first_or_last as Field * rhs_minimum_index;

        // if target_lt_smallest_entry, rhs_index = 0
        // if target_gt_largest_entry, lhs_index = TranscriptEntries - 1
        rhs_index = rhs_index * (1 - target_lt_smallest_entry as Field);

        // we rely here on the fact that target_gt_largest_entry and result_not_first_or_last are mutually exclusive
        lhs_index = lhs_index + target_gt_largest_entry as Field * (N as Field - 1);

        // If target is FOUND, we want the following:
        // keyhash[target_index] - 1 < hash < keyhash[target_index] + 1
        lhs_index = lhs_index + found as Field * found_index;
        rhs_index = rhs_index + found as Field * found_index;

        KeySearchResult {
            found,
            target_lt_smallest_entry,
            target_gt_largest_entry,
            lhs_index,
            rhs_index,
        }
    }

    unconstrained fn __exists(self, idx: Field) -> bool {
        let mut r: bool = false;
        for i in 0..N {
            if (self.keys[i] == idx) {
                r = true;
                break;
            }
        }
        r
    }

    fn get(self, idx: Field) -> Field {
        let search_result = unsafe { self.search_for_key_in_map(idx) };

        let found = search_result.found as Field;

        let target_lt_smallest_entry = search_result.target_lt_smallest_entry as Field;
        let target_gt_largest_entry = search_result.target_gt_largest_entry as Field;

        assert(((search_result.lhs_index - search_result.rhs_index) * found) == 0);

        // only one of "found", "target_lt_smallest_entry", "target_gt_largest_entry" can be true
        let exclusion_test = found + target_gt_largest_entry + target_lt_smallest_entry;
        assert(exclusion_test * exclusion_test == exclusion_test);

        let mut lhs = self.keys[search_result.lhs_index];
        let mut rhs = self.keys[search_result.rhs_index];

        // case where hash < self.key_hashes[0]
        // 0 < hash < hashes[0]
        lhs = lhs * (1 - target_lt_smallest_entry);

        // case where hash > self.key_hashes[last]
        // largest < x < -1
        rhs = rhs * (1 - target_gt_largest_entry) + target_gt_largest_entry * 0x100000000;

        // case where hash == self.key_hashes[found_index]
        lhs = lhs - found;
        rhs = rhs + found;

        (idx - lhs - 1).assert_max_bit_size::<32>();
        (rhs - idx - 1).assert_max_bit_size::<32>();

        (self.maximum - idx - 1).assert_max_bit_size::<32>();

        let value_index = search_result.lhs_index * found;

        let value = self.values[value_index] * found;
        value
    }
}
/**
 * @brief Implements an elliptic curve instantiated over a prime field that is NOT the circuit's native field
 **/
pub struct BigCurve<BigNum, CurveParams> {
    pub x: BigNum,
    pub y: BigNum,
    pub is_infinity: bool,
}

trait CurveParamsTrait<BigNum>
where
    BigNum: BigNumTrait,
{
    fn offset_generator() -> [BigNum; 2];
    fn offset_generator_final() -> [BigNum; 2];
    pub fn one() -> [BigNum; 2];
    pub fn b() -> BigNum;
    pub fn a() -> BigNum;
}

/**
 * @brief A lookup table we use when performing scalar multiplications.
 * @description We slice scalar multiplier into 4 bit chunks represented
 * in windowed non-adjacent form ([-15, -13, ..., 15])
 * We compute a table of point multiples that map to the 4-bit WNAF values T = ([-15[P], -13[P], ..., 15[P]])
 * We set an accumulator to equal T[most significant WNAF slice]
 * We then iterate over our remaining bit slices (starting with most significant slice)
 * For each iteration `i` we double the accumulator 4 times and then add `T[slice[i]]` into the accumulator.
 * For small multiscalar multiplications (i.e. <512 points) this produces the minimal number of addition operations.
 **/
struct PointTable<BigNum> {
    x: [BigNum; 16],
    y: [BigNum; 16],
}

impl<BigNum> PointTable<BigNum>
where
    BigNum: BigNumTrait + std::ops::Add + std::ops::Mul + std::cmp::Eq,
{
    pub(crate) fn empty() -> Self {
        PointTable { x: [BigNum::new(); 16], y: [BigNum::new(); 16] }
    }

    /**
     * @brief Construct a PointTable from an input point and an AffineTranscript that contains required modular inverses
     * (see `CurveJ::mul` for an example of how AffineTranscript objects are generated/used)
     **/
    pub(crate) fn new_with_hint<CurveParams>(
        P: BigCurve<BigNum, CurveParams>,
        transcript: [AffineTranscript<BigNum>; 8],
    ) -> Self
    where
        CurveParams: CurveParamsTrait<BigNum>,
    {
        let mut result = PointTable { x: [BigNum::new(); 16], y: [BigNum::new(); 16] };

        let D2 = P.double_with_hint(transcript[0]);

        result.x[8] = P.x;
        result.y[8] = P.y;
        result.x[7] = P.x;
        result.y[7] = (P.y.neg());

        let mut A = P;
        for i in 1..8 {
            A = D2.incomplete_add_with_hint(A, transcript[i]);
            result.x[8 + i] = A.x;
            result.y[8 + i] = A.y;
            result.x[7 - i] = A.x;
            result.y[7 - i] = (A.y.neg());
        }
        result
    }

    /**
     * @brief get a value out of the lookup table
     * @description if the backend has an efficient implementation of memory lookups,
     * this will be very efficient (~12 constraints for 256-bit curves using the barretenberg backend)
     **/
    pub(crate) fn get<CurveParams>(self, idx: u8) -> BigCurve<BigNum, CurveParams> {
        BigCurve { x: self.x[idx], y: self.y[idx], is_infinity: false }
    }
}

trait BigCurveTrait {
    pub fn neg(self) -> Self;
    pub fn point_at_infinity() -> Self;
    fn offset_generator() -> Self;
    fn offset_generator_final() -> Self;
    pub fn one() -> Self;
    pub fn conditional_select(lhs: Self, rhs: Self, predicate: bool) -> Self;
    pub fn validate_on_curve(self);
    pub fn mul<let NScalarSlices: u32>(self, scalar: ScalarField<NScalarSlices>) -> Self;
    pub fn hash_to_curve<let N: u32>(seed: [u8; N]) -> Self;
}

impl<BigNum, CurveParams> BigCurveTrait for BigCurve<BigNum, CurveParams>
where
    CurveParams: CurveParamsTrait<BigNum>,
    BigNum: BigNumTrait + std::ops::Add + std::ops::Mul + std::cmp::Eq,
{

    fn hash_to_curve<let N: u32>(seed: [u8; N]) -> Self {
        let r = hash_to_curve::<BigNum, N>(seed, CurveParams::a(), CurveParams::b());
        BigCurve { x: r.0, y: r.1, is_infinity: false }
    }

    /**
    * @brief negate a point
    **/
    fn neg(self) -> Self {
        BigCurve { x: self.x, y: self.y.neg(), is_infinity: self.is_infinity }
    }

    fn point_at_infinity() -> Self {
        BigCurve { x: BigNum::new(), y: BigNum::new(), is_infinity: true }
    }

    fn offset_generator() -> Self {
        let result = CurveParams::offset_generator();
        Self { x: result[0], y: result[1], is_infinity: false }
    }

    fn offset_generator_final() -> Self {
        let result = CurveParams::offset_generator_final();
        Self { x: result[0], y: result[1], is_infinity: false }
    }

    fn one() -> Self {
        let result = CurveParams::one();
        Self { x: result[0], y: result[1], is_infinity: false }
    }

    fn conditional_select(lhs: Self, rhs: Self, predicate: bool) -> Self {
        let x = BigNum::conditional_select(lhs.x, rhs.x, predicate);
        let y = BigNum::conditional_select(lhs.y, rhs.y, predicate);
        let is_infinity = (
            (lhs.is_infinity as Field - rhs.is_infinity as Field) * predicate as Field
                + rhs.is_infinity as Field
        ) as bool;
        BigCurve { x, y, is_infinity }
    }

    fn validate_on_curve(self) {
        // if is point at infinity, we're on the curve.
        // In this case just sub in a valid point for the x/y coordinates we are about to test
        let one: Self = BigCurve::one();
        let x: BigNum = BigNum::conditional_select(one.x, self.x, self.is_infinity);
        let y: BigNum = BigNum::conditional_select(one.y, self.y, self.is_infinity);
        let xx = x.mul(x); // hmm?
        //  xxx - yy + ax + b = 0
        // (xx + a) * x - y*y + b = 0
        // validate the provided value of `y3` is correct
        BigNum::evaluate_quadratic_expression(
            [[xx, CurveParams::a()], [y, BigNum::new()]],
            [[false, false], [false, false]],
            [[x], [y]],
            [[false], [true]],
            [CurveParams::b()],
            [false],
        );
    }

    /// 64 * 5 = 320
    // Expensive witness generation! Avoid if possible
    fn mul<let NScalarSlices: u32>(self, scalar: ScalarField<NScalarSlices>) -> Self {
        let transcript: [AffineTranscript<BigNum>; (NScalarSlices * 5) + 6] =
            unsafe { BigCurve::get_mul_transcript(self, scalar) };

        self.mul_with_hint(scalar, transcript)
    }
}

impl<BigNum, CurveParams> BigCurve<BigNum, CurveParams>
where
    CurveParams: CurveParamsTrait<BigNum>,
    BigNum: BigNumTrait + std::ops::Add + std::ops::Mul + std::cmp::Eq,
{

    /**
     * @brief Add two points together, using an AffineTranscript that contains inverses and output witnesses
     * @description Only uses incomplete formulae.
     * With our use of offset generators, an HONEST PROVER should never need to handle edge cases.
     * Therefore we can sacrifice completeness for cheap soundness. Instead of handling edge cases,
     * we simply assert that they do not exist by validating x2 != x1
     * @note This method minimizes the number of calls to `evaluate_quadratic_expression`,
     * which is NOT the same as minimizing the number of multiplications.
     * The expensive operation in BigNum is the modular reduction.
     * e.g. (a * b + c * d = e mod p) is not much more expensive than (a * b = c mod p)
     **/
    fn incomplete_add_with_hint(self, other: Self, transcript: AffineTranscript<BigNum>) -> Self {
        let x1: BigNum = self.x;
        let y1: BigNum = self.y;
        let x2: BigNum = other.x;
        let y2: BigNum = other.y;
        let lambda: BigNum = transcript.lambda;
        let x3: BigNum = transcript.x3;
        let y3: BigNum = transcript.y3;

        // we pulled x3, y3, lambda out of the ether - we need to make sure they are well-formed BigNum objects!
        x3.validate_in_range();
        y3.validate_in_range();
        lambda.validate_in_range();

        // no incomplete Weierstrass shenanigans here
        x1.assert_is_not_equal(x2);

        // validate the provided value of `lambda` is correct
        BigNum::evaluate_quadratic_expression(
            [[lambda]],
            [[false]],
            [[x2, x1]],
            [[false, true]],
            [y2, y1],
            [true, false],
        );

        // validate the provided value of `x3` is correct
        BigNum::evaluate_quadratic_expression(
            [[lambda]],
            [[false]],
            [[lambda]],
            [[false]],
            [x3, x2, x1],
            [true, true, true],
        );

        // validate the provided value of `y3` is correct
        BigNum::evaluate_quadratic_expression(
            [[lambda]],
            [[false]],
            [[x3, x1]],
            [[false, true]],
            [y3, y1],
            [false, false],
        );

        BigCurve { x: x3, y: y3, is_infinity: false }
    }

    fn add_with_hint(self, other: Self, transcript: AffineTranscript<BigNum>) -> Self {
        let mut x1: BigNum = self.x;
        let mut y1: BigNum = self.y;
        let mut x2: BigNum = other.x;
        let mut y2: BigNum = other.y;
        let lambda: BigNum = transcript.lambda;
        let x3: BigNum = transcript.x3;
        let y3: BigNum = transcript.y3;

        // we pulled x3, y3, lambda out of the ether - we need to make sure they are well-formed BigNum objects!
        x3.validate_in_range();
        y3.validate_in_range();
        lambda.validate_in_range();

        // TODO: we can probably optimize this boolean flag jenga mess
        let x_equal_predicate = x2.eq(x1);
        let y_equal_predicate = y2.eq(y1);
        let double_predicate = x_equal_predicate | (self.is_infinity | other.is_infinity); // if x1 == x2, evaluate double operation. If y1 = -y2 then we set all input/output parameters to be 0
        let infinity_predicate =
            (x_equal_predicate & !y_equal_predicate) | (self.is_infinity & other.is_infinity);
        let evaluate_group_operation_predicate: bool =
            !infinity_predicate & !self.is_infinity & !other.is_infinity;

        // If we are skipping the evaluation of a group operation (x2 == x1, y2 == -y1 OR any input points are at infinity),
        // set input operands to 0!
        x1 = BigNum::conditional_select(x1, BigNum::new(), evaluate_group_operation_predicate);
        y1 = BigNum::conditional_select(y1, BigNum::new(), evaluate_group_operation_predicate);
        x2 = BigNum::conditional_select(x2, BigNum::new(), evaluate_group_operation_predicate);
        y2 = BigNum::conditional_select(y2, BigNum::new(), evaluate_group_operation_predicate);

        // lambda * 2y - 3x * x = 0
        // or
        // lambda * (x2 - x1) - (y2 - y1) = 0
        let product_1_rhs_t0 = BigNum::conditional_select(y1, x2, double_predicate);
        let product_1_rhs_t1 = BigNum::conditional_select(y1, x1.neg(), double_predicate);
        let product_2_lhs_t0 = BigNum::conditional_select(x1, BigNum::one(), double_predicate);
        let product_2_rhs_t0 = BigNum::conditional_select(x1, y2, double_predicate);
        let product_2_rhs_t1 = BigNum::conditional_select(x1, y1.neg(), double_predicate);
        let product_2_rhs_t2 = BigNum::conditional_select(x1, BigNum::new(), double_predicate);

        // validate the provided value of `lambda` is correct
        // if double: lambda * (y1 + y1) + x1 * (-x1 -x1 -x1) - a = 0 => lambda * 2y - 3x*x = 0
        // if add:    lambda * (x2 - x1) + 1 * (-y2 + y1) = 0 => lambda * (x2 - x1) - (y2 - y1) = 0
        let mut a_term = BigNum::conditional_select(
            CurveParams::a(),
            BigNum::new(),
            x_equal_predicate & !y_equal_predicate & !self.is_infinity & !other.is_infinity,
        );

        BigNum::evaluate_quadratic_expression(
            [[lambda], [product_2_lhs_t0]],
            [[false], [false]],
            [
                [product_1_rhs_t0, product_1_rhs_t1, BigNum::new()],
                [product_2_rhs_t0, product_2_rhs_t1, product_2_rhs_t2],
            ],
            [[false, false, false], [true, true, true]],
            [a_term],
            [true],
        );

        // x3 = lambda * lambda - x2 - x1
        // if double, then x2 = x1 so we good
        BigNum::evaluate_quadratic_expression(
            [[lambda]],
            [[false]],
            [[lambda]],
            [[false]],
            [x3, x2, x1],
            [true, true, true],
        );

        // y3 = lambda * (x1 - x3) - y1
        BigNum::evaluate_quadratic_expression(
            [[lambda]],
            [[false]],
            [[x3, x1]],
            [[false, true]],
            [y3, y1],
            [false, false],
        );

        let output_is_lhs = other.is_infinity & !self.is_infinity;
        let output_is_rhs = self.is_infinity & !other.is_infinity;
        let mut x_out = BigNum::conditional_select(x3, x1, evaluate_group_operation_predicate);
        x_out = BigNum::conditional_select(self.x, x_out, output_is_lhs);
        x_out = BigNum::conditional_select(other.x, x_out, output_is_rhs);
        x_out = BigNum::conditional_select(BigNum::new(), x_out, infinity_predicate);
        let mut y_out = BigNum::conditional_select(y3, y1, evaluate_group_operation_predicate);
        y_out = BigNum::conditional_select(self.y, y_out, output_is_lhs);
        y_out = BigNum::conditional_select(other.y, y_out, output_is_rhs);
        y_out = BigNum::conditional_select(BigNum::new(), y_out, infinity_predicate);

        let conditional_select = |a: bool, b: bool, predicate: bool| {
            ((a as Field - b as Field) * predicate as Field + b as Field) as bool
        };

        let mut infinity_out = conditional_select(false, true, evaluate_group_operation_predicate);
        infinity_out = conditional_select(true, infinity_out, infinity_predicate);
        infinity_out = conditional_select(self.is_infinity, infinity_out, output_is_lhs);
        infinity_out = conditional_select(other.is_infinity, infinity_out, output_is_rhs);

        let result: Self = BigCurve { x: x_out, y: y_out, is_infinity: infinity_out };
        result
    }

    fn sub_with_hint(self, other: Self, transcript: AffineTranscript<BigNum>) -> Self {
        let mut x1: BigNum = self.x;
        let mut y1: BigNum = self.y;
        let mut x2: BigNum = other.x;
        let mut y2: BigNum = other.y;
        let lambda: BigNum = transcript.lambda;
        let x3: BigNum = transcript.x3;
        let y3: BigNum = transcript.y3;

        // we pulled x3, y3, lambda out of the ether - we need to make sure they are well-formed BigNum objects!
        x3.validate_in_range();
        y3.validate_in_range();
        lambda.validate_in_range();

        let x_equal_predicate = x2.eq(x1);
        let y_equal_predicate = y2.eq(y1) == false;
        let double_predicate = x_equal_predicate | (self.is_infinity | other.is_infinity); // if x1 == x2, evaluate double operation. If y1 = -y2 then we set all input/output parameters to be 0
        let infinity_predicate: bool =
            (x_equal_predicate & !y_equal_predicate) | (self.is_infinity & other.is_infinity);
        let evaluate_group_operation_predicate: bool =
            !infinity_predicate & !self.is_infinity & !other.is_infinity;
        // If we are skipping the evaluation of a group operation (x2 == x1, y2 == -y1 OR any input points are at infinity),
        // set input operands to 0!
        x1 = BigNum::conditional_select(x1, BigNum::new(), evaluate_group_operation_predicate);
        y1 = BigNum::conditional_select(y1, BigNum::new(), evaluate_group_operation_predicate);
        x2 = BigNum::conditional_select(x2, BigNum::new(), evaluate_group_operation_predicate);
        y2 = BigNum::conditional_select(y2, BigNum::new(), evaluate_group_operation_predicate);

        // lambda * 2y - 3x*x = 0
        // 3 x * x - lambda * 2y
        // lambda * (x2 - x1) - (y2 - y1) = 0
        // y1 - (y2.neg()) - lambda * (x1 - x2) = 0
        // y1 + y2 - lambda * (x1 - x2) = 0
        // 3 * x * x - lambda * 2 * y
        let product_1_rhs_t0 = BigNum::conditional_select(y1, x2.neg(), double_predicate);
        let product_1_rhs_t1 = BigNum::conditional_select(y1, x1, double_predicate);
        let product_2_lhs_t0 = BigNum::conditional_select(x1, BigNum::one(), double_predicate);
        let product_2_rhs_t0 = BigNum::conditional_select(x1, y2, double_predicate);
        let product_2_rhs_t1 = BigNum::conditional_select(x1, y1, double_predicate);
        let product_2_rhs_t2 = BigNum::conditional_select(x1, BigNum::new(), double_predicate);

        // validate the provided value of `lambda` is correct
        // if double: -lambda * (y1 + y1) + x1 * (x1 x1 x1) + a= 0 => lambda * 2y - 3x*x = 0
        // if add:    -lambda * (x1 - x2) + 1 * (y2 + y1) = 0 => lambda * (x2 - x1) - (-y2 - y1) = 0
        let mut a_term = BigNum::conditional_select(
            CurveParams::a(),
            BigNum::new(),
            x_equal_predicate & !y_equal_predicate & !self.is_infinity & !other.is_infinity,
        );
        BigNum::evaluate_quadratic_expression(
            [[lambda], [product_2_lhs_t0]],
            [[true], [false]],
            [
                [product_1_rhs_t0, product_1_rhs_t1, BigNum::new()],
                [product_2_rhs_t0, product_2_rhs_t1, product_2_rhs_t2],
            ],
            [[false, false, false], [false, false, false]],
            [a_term],
            [false],
        );

        // x3 = lambda * lambda - x2 - x1
        // if double, then x2 = x1 so we good
        BigNum::evaluate_quadratic_expression(
            [[lambda]],
            [[false]],
            [[lambda]],
            [[false]],
            [x3, x2, x1],
            [true, true, true],
        );

        // y3 = lambda * (x1 - x3) - y1
        BigNum::evaluate_quadratic_expression(
            [[lambda]],
            [[false]],
            [[x3, x1]],
            [[false, true]],
            [y3, y1],
            [false, false],
        );

        let output_is_lhs = other.is_infinity & !self.is_infinity;
        let output_is_rhs = self.is_infinity & !other.is_infinity;
        let mut x_out = BigNum::conditional_select(x3, x1, evaluate_group_operation_predicate);
        x_out = BigNum::conditional_select(self.x, x_out, output_is_lhs);
        x_out = BigNum::conditional_select(other.x, x_out, output_is_rhs);
        x_out = BigNum::conditional_select(BigNum::new(), x_out, infinity_predicate);
        let mut y_out = BigNum::conditional_select(y3, y1, evaluate_group_operation_predicate);
        y_out = BigNum::conditional_select(self.y, y_out, output_is_lhs);
        y_out = BigNum::conditional_select(other.y.neg(), y_out, output_is_rhs);
        y_out = BigNum::conditional_select(BigNum::new(), y_out, infinity_predicate);

        let conditional_select = |a: bool, b: bool, predicate: bool| {
            ((a as Field - b as Field) * predicate as Field + b as Field) as bool
        };

        let mut infinity_out = conditional_select(false, true, evaluate_group_operation_predicate);
        infinity_out = conditional_select(true, infinity_out, infinity_predicate);
        infinity_out = conditional_select(self.is_infinity, infinity_out, output_is_lhs);
        infinity_out = conditional_select(other.is_infinity, infinity_out, output_is_rhs);

        let result: Self = BigCurve { x: x_out, y: y_out, is_infinity: infinity_out };
        result
    }

    fn incomplete_subtract_with_hint(
        self,
        other: Self,
        transcript: AffineTranscript<BigNum>,
    ) -> Self {
        let x1: BigNum = self.x;
        let y1: BigNum = self.y;
        let x2: BigNum = other.x;
        let y2: BigNum = other.y;
        let lambda: BigNum = transcript.lambda;
        let x3: BigNum = transcript.x3;
        let y3: BigNum = transcript.y3;

        // we pulled x3, y3, lambda out of the ether - we need to make sure they are well-formed BigNum objects!
        x3.validate_in_range();
        y3.validate_in_range();
        lambda.validate_in_range();

        // no incomplete Weierstrass shenanigans here
        x1.assert_is_not_equal(x2);

        // validate the provided value of `lambda` is correct
        BigNum::evaluate_quadratic_expression(
            [[lambda]],
            [[false]],
            [[x2, x1]],
            [[false, true]],
            [y2, y1],
            [false, false],
        );

        // validate the provided value of `x3` is correct
        BigNum::evaluate_quadratic_expression(
            [[lambda]],
            [[false]],
            [[lambda]],
            [[false]],
            [x3, x2, x1],
            [true, true, true],
        );

        // validate the provided value of `y3` is correct
        BigNum::evaluate_quadratic_expression(
            [[lambda]],
            [[false]],
            [[x3, x1]],
            [[false, true]],
            [y3, y1],
            [false, false],
        );

        BigCurve { x: x3, y: y3, is_infinity: false }
    }

    fn conditional_incomplete_add_with_hint(
        self,
        other: Self,
        predicate: bool,
        transcript: AffineTranscript<BigNum>,
    ) -> Self {
        let operand_output = self.incomplete_add_with_hint(other, transcript);
        let result = BigCurve::conditional_select(operand_output, self, predicate);
        result
    }

    fn conditional_incomplete_subtract_with_hint(
        self,
        other: Self,
        predicate: bool,
        transcript: AffineTranscript<BigNum>,
    ) -> Self {
        let operand_output = self.incomplete_subtract_with_hint(other, transcript);
        let result = BigCurve::conditional_select(operand_output, self, predicate);
        result
    }

    /**
     * @brief Double a point, using an AffineTranscript that contains inverses and output witnesses
     * @note This method minimizes the number of calls to `evalute_quadratic_expression`,
     * which is NOT the same as minimizing the number of multiplications.
     **/
    fn double_with_hint(self, transcript: AffineTranscript<BigNum>) -> Self {
        let x1: BigNum = self.x;
        let y1: BigNum = self.y;
        let lambda: BigNum = transcript.lambda;
        let x3: BigNum = transcript.x3;
        let y3: BigNum = transcript.y3;

        // TODO: HANDLE CURVES WHERE A != 0
        // we pulled x3, y3, lambda out of the ether - we need to make sure they are well-formed BigNum objects!
        x3.validate_in_range();
        y3.validate_in_range();
        lambda.validate_in_range();

        // -lambda * 2y + 3*x*x + a = 0
        // validate the provided value of `lambda` is correct
        // n.b. if CurveParams::a() == 0, its inclusion shouldn't cost extra constraints...I thnk
        BigNum::evaluate_quadratic_expression(
            [[x1, x1, x1], [y1, y1, BigNum::new()]],
            [[false, false, false], [false, false, false]],
            [[x1], [lambda]],
            [[false], [true]],
            [CurveParams::a()],
            [false],
        );

        // validate the provided value of `x3` is correct
        BigNum::evaluate_quadratic_expression(
            [[lambda]],
            [[false]],
            [[lambda]],
            [[false]],
            [x3, x1, x1],
            [true, true, true],
        );

        // validate the provided value of `y3` is correct
        BigNum::evaluate_quadratic_expression(
            [[lambda]],
            [[false]],
            [[x3, x1]],
            [[false, true]],
            [y3, y1],
            [false, false],
        );

        BigCurve { x: x3, y: y3, is_infinity: false }
    }

    /**
     * @brief Perform an ecc scalar multiplication, given an [AffineTranscript] generated via unconstrained functions
     **/
    fn mul_with_hint<let NScalarSlices: u32, let NTranscriptSlices: u32>(
        self,
        scalar: ScalarField<NScalarSlices>,
        transcript: [AffineTranscript<BigNum>; NTranscriptSlices],
    ) -> Self {
        // Compute a 4-bit lookup table of multiples of P
        let input: Self = BigCurve::conditional_select(BigCurve::one(), self, self.is_infinity);
        let scalar: ScalarField<NScalarSlices> =
            ScalarField::conditional_select(ScalarField::zero(), scalar, self.is_infinity);

        let T: PointTable<BigNum> = PointTable::new_with_hint(
            input,
            [
                transcript[0],
                transcript[1],
                transcript[2],
                transcript[3],
                transcript[4],
                transcript[5],
                transcript[6],
                transcript[7],
            ],
        );

        // Init the accumulator from the most significant scalar slice
        let mut accumulator: Self = BigCurve::offset_generator();
        let mut accumulator =
            accumulator.incomplete_add_with_hint(T.get(scalar.base4_slices[0]), transcript[3 + 5]);

        // Perform the "double and add" algorithm but in steps of 4 bits, using the lookup table T to extract 4-bit multiples of P
        for i in 1..NScalarSlices {
            accumulator = accumulator.double_with_hint(transcript[4 + 5 * i]);
            accumulator = accumulator.double_with_hint(transcript[5 + 5 * i]);
            accumulator = accumulator.double_with_hint(transcript[6 + 5 * i]);
            accumulator = accumulator.double_with_hint(transcript[7 + 5 * i]);
            accumulator = accumulator.incomplete_add_with_hint(
                T.get(scalar.base4_slices[i]),
                transcript[8 + 5 * i],
            );
        }

        // windowed non-adjacent form can only represent odd scalar values.
        // if value is even, the result will be off by one and we need to subtract the input point
        accumulator = accumulator.conditional_incomplete_subtract_with_hint(
            input,
            scalar.skew,
            transcript[4 + 5 * NScalarSlices],
        );

        accumulator = accumulator.sub_with_hint(
            BigCurve::offset_generator_final(),
            transcript[5 + 5 * NScalarSlices],
        );
        accumulator
    }

    // TODO: offset generators
    //       conditional subtract, conditional add
    //
    /**
     * @brief Perform an ecc scalar multiplication, given an [AffineTranscript] generated via unconstrained functions
     **/
    fn msm_with_hint_internal<let Size: u32, let NScalarSlices: u32, let NTranscriptSlices: u32>(
        mut points: [Self; Size],
        mut scalars: [ScalarField<NScalarSlices>; Size],
        transcript: [AffineTranscript<BigNum>; NTranscriptSlices],
    ) -> Self {
        // Compute a 4-bit lookup table of multiples of P
        let mut _inputs: [Self; Size] = [BigCurve::one(); Size];
        let mut _scalars: [ScalarField<NScalarSlices>; Size] = [ScalarField::new(); Size];
        for i in 0..Size {
            _inputs[i] =
                BigCurve::conditional_select(BigCurve::one(), points[i], points[i].is_infinity);
            _scalars[i] = ScalarField::conditional_select(
                ScalarField::zero(),
                scalars[i],
                points[i].is_infinity,
            );
        }
        points = _inputs;
        scalars = _scalars;

        let mut tables: [PointTable<BigNum>; Size] = [PointTable::empty(); Size];
        for i in 0..Size {
            let mut table_transcript: [AffineTranscript<BigNum>; 8] = [AffineTranscript::new(); 8];
            for j in 0..8 {
                table_transcript[j] = transcript[i * 8 + j];
            }
            tables[i] = PointTable::new_with_hint(points[i], table_transcript);
        }

        // Init the accumulator from the most significant scalar slice
        let mut accumulator: Self = BigCurve::offset_generator();
        let mut accumulator = accumulator.incomplete_add_with_hint(
            tables[0].get(scalars[0].base4_slices[0]),
            transcript[8 * Size],
        );

        for i in 1..Size {
            accumulator = accumulator.incomplete_add_with_hint(
                tables[i].get(scalars[i].base4_slices[0]),
                transcript[8 * Size + i],
            );
        }

        // Perform the "double and add" algorithm but in steps of 4 bits, using the lookup table T to extract 4-bit multiples of P
        for i in 1..NScalarSlices {
            accumulator = accumulator.double_with_hint(transcript[9 * Size + (4 + Size) * (i - 1)]);
            accumulator =
                accumulator.double_with_hint(transcript[9 * Size + (4 + Size) * (i - 1) + 1]);
            accumulator =
                accumulator.double_with_hint(transcript[9 * Size + (4 + Size) * (i - 1) + 2]);
            accumulator =
                accumulator.double_with_hint(transcript[9 * Size + (4 + Size) * (i - 1) + 3]);

            for j in 0..Size {
                accumulator = accumulator.incomplete_add_with_hint(
                    tables[j].get(scalars[j].base4_slices[i]),
                    transcript[9 * Size + (4 + Size) * (i - 1) + 4 + j],
                );
            }
        }

        // 9 * Size + (4 + Size) * (NScalarSlices - 1) - 1
        // 9 + 5 * NScalarSlices - 6
        // windowed non-adjacent form can only represent odd scalar values.
        // if value is even, the result will be off by one and we need to subtract the input point
        for i in 0..Size {
            accumulator = accumulator.conditional_incomplete_subtract_with_hint(
                points[i],
                scalars[i].skew,
                transcript[9 * Size + (4 + Size) * (NScalarSlices - 1) + i],
            );
        }

        accumulator
    }

    fn msm_with_hint<let Size: u32, let NScalarSlices: u32, let NTranscriptSlices: u32>(
        mut points: [Self; Size],
        mut scalars: [ScalarField<NScalarSlices>; Size],
        transcript: [AffineTranscript<BigNum>; NTranscriptSlices],
    ) -> Self {
        let mut accumulator = BigCurve::msm_with_hint_internal(points, scalars, transcript);
        accumulator = accumulator.sub_with_hint(
            BigCurve::offset_generator_final(),
            transcript[10 * Size + (4 + Size) * (NScalarSlices - 1)],
        );
        accumulator
    }

    unconstrained fn get_mul_transcript<let NScalarSlices: u32>(
        P: Self,
        scalar: ScalarField<NScalarSlices>,
    ) -> [AffineTranscript<BigNum>; 6 + NScalarSlices * 5] {
        CurveJ::from(P).mul(scalar).1.as_array()
    }

    pub fn msm<let NScalarSlices: u32, let NMuls: u32>(
        mul_points: [Self; NMuls],
        mul_scalars: [ScalarField<NScalarSlices>; NMuls],
    ) -> Self {
        BigCurve::evaluate_linear_expression(mul_points, mul_scalars, [])
    }

    pub fn evaluate_linear_expression<let NScalarSlices: u32, let NMuls: u32, let NAdds: u32>(
        mul_points: [Self; NMuls],
        mul_scalars: [ScalarField<NScalarSlices>; NMuls],
        add_points: [Self; NAdds],
    ) -> Self {
        let transcript: [AffineTranscript<BigNum>; NScalarSlices * NMuls + NScalarSlices * 4 + NMuls * 9 + NAdds - 3] = unsafe {
            CurveJ::compute_linear_expression_transcript(mul_points, mul_scalars, add_points).1
        };
        let mut _inputs: [Self; NMuls] = [BigCurve::one(); NMuls];
        let mut _scalars: [ScalarField<NScalarSlices>; NMuls] = [ScalarField::new(); NMuls];
        for i in 0..NMuls {
            _inputs[i] = BigCurve::conditional_select(
                BigCurve::one(),
                mul_points[i],
                mul_points[i].is_infinity,
            );
            _scalars[i] = ScalarField::conditional_select(
                ScalarField::zero(),
                mul_scalars[i],
                mul_points[i].is_infinity,
            );
        }
        let msm_points = _inputs;
        let scalars = _scalars;

        let mut tables: [PointTable<BigNum>; NMuls] = [PointTable::empty(); NMuls];
        for i in 0..NMuls {
            let mut table_transcript: [AffineTranscript<BigNum>; 8] = [AffineTranscript::new(); 8];
            for j in 0..8 {
                table_transcript[j] = transcript[i * 8 + j];
            }
            tables[i] = PointTable::new_with_hint(msm_points[i], table_transcript);
        }

        // Init the accumulator from the most significant scalar slice
        let mut accumulator: Self = BigCurve::offset_generator();
        let mut accumulator = accumulator.incomplete_add_with_hint(
            tables[0].get(scalars[0].base4_slices[0]),
            transcript[8 * NMuls],
        );
        for i in 1..NMuls {
            accumulator = accumulator.incomplete_add_with_hint(
                tables[i].get(scalars[i].base4_slices[0]),
                transcript[8 * NMuls + i],
            );
        }

        // Perform the "double and add" algorithm but in steps of 4 bits, using the lookup table T to extract 4-bit multiples of P
        for i in 1..NScalarSlices {
            accumulator =
                accumulator.double_with_hint(transcript[9 * NMuls + (4 + NMuls) * (i - 1)]);
            accumulator =
                accumulator.double_with_hint(transcript[9 * NMuls + (4 + NMuls) * (i - 1) + 1]);
            accumulator =
                accumulator.double_with_hint(transcript[9 * NMuls + (4 + NMuls) * (i - 1) + 2]);
            accumulator =
                accumulator.double_with_hint(transcript[9 * NMuls + (4 + NMuls) * (i - 1) + 3]);
            for j in 0..NMuls {
                accumulator = accumulator.incomplete_add_with_hint(
                    tables[j].get(scalars[j].base4_slices[i]),
                    transcript[9 * NMuls + (4 + NMuls) * (i - 1) + 4 + j],
                );
            }
        }

        // 9 * Size + (4 + Size) * (NScalarSlices - 1) - 1
        // 9 + 5 * NScalarSlices - 6
        // windowed non-adjacent form can only represent odd scalar values.
        // if value is even, the result will be off by one and we need to subtract the input point
        for i in 0..NMuls {
            accumulator = accumulator.conditional_incomplete_subtract_with_hint(
                msm_points[i],
                scalars[i].skew,
                transcript[9 * NMuls + (4 + NMuls) * (NScalarSlices - 1) + i],
            );
        }

        for i in 0..NAdds {
            accumulator = accumulator.conditional_incomplete_add_with_hint(
                add_points[i],
                !add_points[i].is_infinity,
                transcript[10 * NMuls + (4 + NMuls) * (NScalarSlices - 1) + i],
            );
        }

        accumulator = accumulator.sub_with_hint(
            BigCurve::offset_generator_final(),
            transcript[NScalarSlices * NMuls + NScalarSlices * 4 + NMuls * 9 + NAdds - 4],
        );

        accumulator
    }
}

impl<BigNum, CurveParams> std::ops::Add for BigCurve<BigNum, CurveParams>
where
    CurveParams: CurveParamsTrait<BigNum>,
    BigNum: BigNumTrait + std::ops::Add + std::ops::Mul + std::cmp::Eq,
{
    // Expensive witness generation! Avoid if possible
    fn add(self, other: Self) -> Self {
        let lhsJ = CurveJ::from(self);
        let rhsJ = CurveJ::from(other);

        let transcript = unsafe { AffineTranscript::from_j(lhsJ.add(rhsJ).1) };

        self.add_with_hint(other, transcript)
    }
}

impl<BigNum, CurveParams> std::ops::Sub for BigCurve<BigNum, CurveParams>
where
    CurveParams: CurveParamsTrait<BigNum>,
    BigNum: BigNumTrait + std::ops::Add + std::ops::Mul + std::cmp::Eq,
{
    // Expensive witness generation! Avoid if possible
    fn sub(self, other: Self) -> Self {
        let lhsJ = CurveJ::from(self);
        let rhsJ = CurveJ::from(other);

        let transcript = unsafe { AffineTranscript::from_j(lhsJ.sub(rhsJ).1) };

        self.sub_with_hint(other, transcript)
    }
}

/**
 * @brief are two Affine points equal?
 **/
impl<BigNum, CurveParams> std::cmp::Eq for BigCurve<BigNum, CurveParams>
where
    BigNum: BigNumTrait + std::ops::Add + std::ops::Mul + std::cmp::Eq,
{
    fn eq(self, other: Self) -> bool {
        let coords_equal =
            self.x.eq(other.x) & self.y.eq(other.y) & !self.is_infinity & !other.is_infinity;
        let infinity = self.is_infinity & other.is_infinity;
        coords_equal | infinity
    }
}
