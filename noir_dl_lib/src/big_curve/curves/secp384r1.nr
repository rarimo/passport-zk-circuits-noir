use crate::bignum::BigNum;
use crate::bignum::fields::secp384r1Fq::Secp384r1_Fq_Params;
use crate::bignum::fields::secp384r1Fr::Secp384r1_Fr_Params;
use crate::big_curve::CurveParamsTrait;
use crate::big_curve::BigCurve;
use crate::big_curve::scalar_field::ScalarField;

pub struct Secp384r1_Params {}
impl CurveParamsTrait<BigNum<4, 384, Secp384r1_Fq_Params>> for Secp384r1_Params {
    fn a() -> BigNum<4, 384, Secp384r1_Fq_Params> {
        BigNum {
            limbs: [
                0xffffff0000000000000000fffffffc,
                0xfffffffffffffffffffffffffffeff,
                0xffffffffffffffffffffffffffffff,
                0xffffff,
            ],
        }
    }
    fn b() -> BigNum<4, 384, Secp384r1_Fq_Params> {
        BigNum {
            limbs: [
                0x56398d8a2ed19d2a85c8edd3ec2aef,
                0x9c6efe8141120314088f5013875ac6,
                0xa7e23ee7e4988e056be3f82d19181d,
                0xb3312f,
            ],
        }
    }
    fn one() -> [BigNum<4, 384, Secp384r1_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [
                    0x02f25dbf55296c3a545e3872760ab7,
                    0x3b628ba79b9859f741e082542a3855,
                    0x22be8b05378eb1c71ef320ad746e1d,
                    0xaa87ca,
                ],
            },
            BigNum {
                limbs: [
                    0x60b1ce1d7e819d7a431d7c90ea0e5f,
                    0x1dbd289a147ce9da3113b5f0b8c00a,
                    0x4a96262c6f5d9e98bf9292dc29f8f4,
                    0x3617de,
                ],
            },
        ]
    }
    fn offset_generator() -> [BigNum<4, 384, Secp384r1_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [
                    0xba62f5015d975e9c847349dc8a58f7,
                    0xcfe0a3905b8dafff0226cbfddee8d3,
                    0xce72424b249140226ac9b8afb0ab3c,
                    0xffb219,
                ],
            },
            BigNum {
                limbs: [
                    0x889e51064a7515c4b3a96a397501de,
                    0xfe7bbfa55a3b86cf38c1e0bce169de,
                    0xb19d05c22e1590952e5a956ddcb3bd,
                    0x462005,
                ],
            },
        ]
    }
    fn offset_generator_final() -> [BigNum<4, 384, Secp384r1_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [
                    0xce701d9971f92d5e54d393c5e68585,
                    0x7075dbe299c8708a1e0ec78c96a60f,
                    0x393d1f969e37931c99fb298e53630d,
                    0x364fe7,
                ],
            },
            BigNum {
                limbs: [
                    0x8301c0d245c908e4f5c4e20c98a696,
                    0xb48327458c410785bab4bd29b71040,
                    0xe9536dfb1bd0b1c80c04e2e1ef404e,
                    0x40d30a,
                ],
            },
        ]
    }
}

pub global SECP384r1_SCALAR_SLICES: u32 = 97;
pub type Secp384r1 = BigCurve<BigNum<4, 384, Secp384r1_Fq_Params>, Secp384r1_Params>;
pub type Secp384r1Scalar = ScalarField<SECP384r1_SCALAR_SLICES>;
pub type Secp384r1Fq = BigNum<4, 384, Secp384r1_Fq_Params>;
pub type Secp384r1Fr = BigNum<4, 384, Secp384r1_Fr_Params>;

