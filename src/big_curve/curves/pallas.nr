use crate::bignum::BigNum;
use crate::bignum::fields::pallasFr::Pallas_Fr_Params;
use crate::bignum::fields::pallasFq::Pallas_Fq_Params;
use crate::big_curve::BigCurve;
use crate::big_curve::scalar_field::ScalarField;
use crate::big_curve::CurveParamsTrait;

global PALLAS_SCALAR_SLICES: u32 = 64;

pub struct Pallas_Params {}
impl CurveParamsTrait<BigNum<3, 255, Pallas_Fq_Params>> for Pallas_Params {
    fn a() -> BigNum<3, 255, Pallas_Fq_Params> {
        BigNum { limbs: [0x00, 0x00, 0x00] }
    }
    fn b() -> BigNum<3, 255, Pallas_Fq_Params> {
        BigNum { limbs: [0x05, 0x00, 0x00] }
    }
    fn one() -> [BigNum<3, 255, Pallas_Fq_Params>; 2] {
        [
            BigNum { limbs: [0x4698fc094cf91b992d30ed00000000, 0x22, 0x4000] },
            BigNum { limbs: [0x02, 0x00, 0x00] },
        ]
    }
    fn offset_generator() -> [BigNum<3, 255, Pallas_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [0xd2422812b398350c1aebba48ec188a, 0xb131381b40fe8f0a2a6379eb41d224, 0x241a],
            },
            BigNum {
                limbs: [0x0b9046b0869b1629091d1fa9f16692, 0xc5dec5f6d150a01e8529316736e0fa, 0x2c49],
            },
        ]
    }
    fn offset_generator_final() -> [BigNum<3, 255, Pallas_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [0x8d735ee60f0b794209ba47e69517b5, 0x0268fe41698522f06c1f464e5425f6, 0x1e33],
            },
            BigNum {
                limbs: [0xbd45401bf9c27bf9dd24a5ce54ce87, 0x47abf9cd0515d86bf76d53b264cfcc, 0x072a],
            },
        ]
    }
}

pub type Pallas = BigCurve<BigNum<3, 255, Pallas_Fq_Params>, Pallas_Params>;
pub type PallasScalar = ScalarField<PALLAS_SCALAR_SLICES>;
pub type PallasFq = BigNum<3, 255, Pallas_Fq_Params>;
pub type PallasFr = BigNum<3, 255, Pallas_Fr_Params>;

