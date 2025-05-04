use crate::bignum::BigNum;
use super::params::Secp224r1_Fq_Params;
use crate::big_curve::CurveParamsTrait;


pub global SECP224r1_SCALAR_SLICES: u32 = 57;
pub struct Secp224r1_Params {}
impl CurveParamsTrait<BigNum<2, 224, Secp224r1_Fq_Params>> for Secp224r1_Params {
    fn a() -> BigNum<2, 224, Secp224r1_Fq_Params> {
        BigNum {
            limbs: [0xfffffefffffffffffffffffffffffe, 0xffffffffffffffffffffffffff]
        }
    }
    fn b() -> BigNum<2, 224, Secp224r1_Fq_Params> {
        BigNum {
            limbs: {
                [0x44b0b7d7bfd8ba270b39432355ffb4, 0xb4050a850c04b3abf541325650]
            },
        }
    }

    fn offset_generator() -> [BigNum<2, 224, Secp224r1_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [
                    0,
                    0,
                ],
            },
            BigNum {
                limbs: [
                   0,
                   0,
                ],
            },
        ]
    }

    fn offset_generator_final() -> [BigNum<2, 224, Secp224r1_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [
                   0,
                   0,
                ],
            },
            BigNum {
                limbs: [
                  0, 
                  0,
                ],
            },
        ]
    }

    fn one() -> [BigNum<2, 224, Secp224r1_Fq_Params>; 2] {
        [
            BigNum {
                limbs: {
                   [0x3c1d356c21122343280d6115c1d21, 0xb70e0cbd6bb4bf7f321390b94a]
                },
            },
            BigNum {
                limbs: {
                   [0x4375a05a07476444d5819985007e34, 0xbd376388b5f723fb4c22dfe6cd]
                },
            },
        ]
    }
}
