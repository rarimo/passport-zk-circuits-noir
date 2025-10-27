use crate::bignum::BigNum;
use crate::bignum::fields::secp256k1Fq::Secp256k1_Fq_Params;
use crate::bignum::fields::secp256k1Fr::Secp256k1_Fr_Params;
use crate::big_curve::CurveParamsTrait;
use crate::big_curve::BigCurve;
use crate::big_curve::scalar_field::ScalarField;

global SECP256k1_SCALAR_SLICES: u32 = 65;
pub struct Secp256k1_Params {}
impl CurveParamsTrait<BigNum<3, 256, Secp256k1_Fq_Params>> for Secp256k1_Params {
    fn a() -> BigNum<3, 256, Secp256k1_Fq_Params> {
        BigNum { limbs: [0x00, 0x00, 0x00] }
    }
    fn b() -> BigNum<3, 256, Secp256k1_Fq_Params> {
        BigNum { limbs: [0x07, 0x00, 0x00] }
    }
    fn one() -> [BigNum<3, 256, Secp256k1_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [0x9bfcdb2dce28d959f2815b16f81798, 0x667ef9dcbbac55a06295ce870b0702, 0x79be],
            },
            BigNum {
                limbs: [0x17b448a68554199c47d08ffb10d4b8, 0xda7726a3c4655da4fbfc0e1108a8fd, 0x483a],
            },
        ]
    }
    fn offset_generator() -> [BigNum<3, 256, Secp256k1_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [0x7f497cc0b274831d60a9a05d29677e, 0x08726557bf1dd4a0bfdc80ba0f6f13, 0x9046],
            },
            BigNum {
                limbs: [0xfc449b9f63f4ec1c94bd9e3d802229, 0x63b03856445a4b7d349c9a184f81ac, 0x8d48],
            },
        ]
    }
    fn offset_generator_final() -> [BigNum<3, 256, Secp256k1_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [0x36e6c375bf85dd5b9f64e908eedd44, 0xddca5c990b1b1000dfc199cb21c0e9, 0xd913],
            },
            BigNum {
                limbs: [0xf863897dd8147d74af6c9b62d49be6, 0xc1388d9280f314b0acd7fb4ce979b9, 0x2bf7],
            },
        ]
    }
}

pub type Secp256k1 = BigCurve<BigNum<3, 256, Secp256k1_Fq_Params>, Secp256k1_Params>;
pub type Secp256k1Scalar = ScalarField<SECP256k1_SCALAR_SLICES>;
pub type Secp256k1Fq = BigNum<3, 256, Secp256k1_Fq_Params>;
pub type Secp256k1Fr = BigNum<3, 256, Secp256k1_Fr_Params>;
