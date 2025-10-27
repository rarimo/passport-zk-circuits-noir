use crate::bignum::BigNum;
use crate::bignum::fields::bls12_377Fq::BLS12_377_Fq_Params;
use crate::bignum::fields::bls12_377Fr::BLS12_377_Fr_Params;
use crate::big_curve::CurveParamsTrait;
use crate::big_curve::BigCurve;
use crate::big_curve::scalar_field::ScalarField;

global BLS12_377_SCALAR_SLICES: u32 = 64;
pub struct BLS12_377_Params {}
impl CurveParamsTrait<BigNum<4, 377, BLS12_377_Fq_Params>> for BLS12_377_Params {
    fn a() -> BigNum<4, 377, BLS12_377_Fq_Params> {
        BigNum { limbs: [0x00, 0x00, 0x00, 0x00] }
    }
    fn b() -> BigNum<4, 377, BLS12_377_Fq_Params> {
        BigNum { limbs: [0x01, 0x00, 0x00, 0x00] }
    }
    fn one() -> [BigNum<4, 377, BLS12_377_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [
                    0x481512ffcd394eeab9b16eb21be9ef,
                    0x1e2caa9d41bb188282c8bd37cb5cd5,
                    0xdefe740a67c8fc6225bf87ff548595,
                    0x8848,
                ],
            },
            BigNum {
                limbs: [
                    0xfe3d3634a9591afd82de55559c8ea6,
                    0xb348ca3e52d96d182ad44fb82305c2,
                    0x69c5102eff1f674f5d30afeec4bd7f,
                    0x01914a,
                ],
            },
        ]
    }
    fn offset_generator() -> [BigNum<4, 377, BLS12_377_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [
                    0xba342dd2e8a57e30e4fab3aac114b2,
                    0x6e7346ab4fea7f55a1f08939754a50,
                    0x6412e09f423388a318b8a4d36a0072,
                    0x3eb8,
                ],
            },
            BigNum {
                limbs: [
                    0x8a796bd31648b17a897fce57b28356,
                    0x2e1d2547bb3228e76b01175312545b,
                    0x9accab8b8165af3afa1a90cb152ecd,
                    0xa0e9,
                ],
            },
        ]
    }
    fn offset_generator_final() -> [BigNum<4, 377, BLS12_377_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [
                    0x671498ee656f13e9b769355538d6a5,
                    0x50f93aaeb8c9ffbd231d89d655a66e,
                    0xab51ed158495b9e4459d72be5ef856,
                    0x01ab35,
                ],
            },
            BigNum {
                limbs: [
                    0x7e1116c8a65727559685d7c70063ff,
                    0xf16bb13f725cac296ddbd1bd54515c,
                    0x892af9d72f0a7eeeee28cce211e07c,
                    0x9991,
                ],
            },
        ]
    }
}

pub type BLS12_377 = BigCurve<BigNum<4, 377, BLS12_377_Fq_Params>, BLS12_377_Params>;
pub type BLS12_377Scalar = ScalarField<BLS12_377_SCALAR_SLICES>;
pub type BLS12_377Fq = BigNum<4, 377, BLS12_377_Fq_Params>;
pub type BLS12_377Fr = BigNum<3, 253, BLS12_377_Fr_Params>;

