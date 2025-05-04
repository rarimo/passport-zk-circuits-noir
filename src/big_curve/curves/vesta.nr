use crate::bignum::BigNum;
use crate::bignum::fields::vestaFq::Vesta_Fq_Params;
use crate::bignum::fields::vestaFr::Vesta_Fr_Params;
use crate::big_curve::CurveParamsTrait;
use crate::big_curve::BigCurve;
use crate::big_curve::scalar_field::ScalarField;

pub struct Vesta_Params {}
impl CurveParamsTrait<BigNum<3, 255, Vesta_Fq_Params>> for Vesta_Params {
    fn a() -> BigNum<3, 255, Vesta_Fq_Params> {
        BigNum { limbs: [0x00, 0x00, 0x00] }
    }
    fn b() -> BigNum<3, 255, Vesta_Fq_Params> {
        BigNum { limbs: [0x05, 0x00, 0x00] }
    }
    fn one() -> [BigNum<3, 255, Vesta_Fq_Params>; 2] {
        [
            BigNum { limbs: [0x4698fc0994a8dd8c46eb2100000000, 0x22, 0x4000] },
            BigNum { limbs: [0x02, 0x00, 0x00] },
        ]
    }
    fn offset_generator() -> [BigNum<3, 255, Vesta_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [0xd6286ae8e92203a8122b1827a9b6d1, 0xcd21322ea03ceea814cfd7137b4a13, 0x0116],
            },
            BigNum {
                limbs: [0x6c4531e4384d03f3c0febb060cbe74, 0xabaae719efbfcf4a24508d1596c758, 0x2190],
            },
        ]
    }
    fn offset_generator_final() -> [BigNum<3, 255, Vesta_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [0xa87902cfed63db9fdaa5a570a4938d, 0x1d99860422926bca663f59f047ce18, 0x1083],
            },
            BigNum {
                limbs: [0x9fa3943f857b1178d7242101da6c4c, 0xa67fd5354fcf62d204d7ad617adb6c, 0x0a9f],
            },
        ]
    }
}

pub global VESTA_SCALAR_SLICES: u32 = 64;
pub type Vesta = BigCurve<BigNum<3, 255, Vesta_Fq_Params>, Vesta_Params>;
pub type VestaScalar = ScalarField<VESTA_SCALAR_SLICES>;
pub type VestaFq = BigNum<3, 255, Vesta_Fq_Params>;
pub type VestaFr = BigNum<3, 255, Vesta_Fr_Params>;
