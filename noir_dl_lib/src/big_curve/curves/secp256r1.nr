use crate::bignum::BigNum;
use crate::bignum::fields::secp256r1Fq::Secp256r1_Fq_Params;
use crate::bignum::fields::secp256r1Fr::Secp256r1_Fr_Params;
use crate::big_curve::CurveParamsTrait;
use crate::big_curve::BigCurve;
use crate::big_curve::scalar_field::ScalarField;

pub struct Secp256r1_Params {}
impl CurveParamsTrait<BigNum<3, 256, Secp256r1_Fq_Params>> for Secp256r1_Params {
    fn a() -> BigNum<3, 256, Secp256r1_Fq_Params> {
        BigNum { limbs: [0xfffffffffffffffffffffffc, 0xffff00000001000000000000000000, 0xffff] }
    }
    fn b() -> BigNum<3, 256, Secp256r1_Fq_Params> {
        BigNum {
            limbs: [0x1d06b0cc53b0f63bce3c3e27d2604b, 0x35d8aa3a93e7b3ebbd55769886bc65, 0x5ac6],
        }
    }
    fn one() -> [BigNum<3, 256, Secp256r1_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [0x037d812deb33a0f4a13945d898c296, 0xd1f2e12c4247f8bce6e563a440f277, 0x6b17],
            },
            BigNum {
                limbs: [0xce33576b315ececbb6406837bf51f5, 0x42e2fe1a7f9b8ee7eb4a7c0f9e162b, 0x4fe3],
            },
        ]
    }
    fn offset_generator() -> [BigNum<3, 256, Secp256r1_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [0x43a84352fdbca907cb6bcdc31f4784, 0x02b728fe767007b08d0ced4ccf0591, 0x5c14],
            },
            BigNum {
                limbs: [0x664a12c8ee78446ee947a8a109adfe, 0x445dd71ff484b877a5bf3df6263bfc, 0x841b],
            },
        ]
    }
    fn offset_generator_final() -> [BigNum<3, 256, Secp256r1_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [0x4e53e542bc502419d0cb4b99c0aa48, 0x74d3a045b26542b1a5931d721650ab, 0x6982],
            },
            BigNum {
                limbs: [0xbe3c1ef0581c8f76517e499277b269, 0xfd562740986614ce3b7025c0dfb8aa, 0xfc88],
            },
        ]
    }
}

pub global SECP256r1_SCALAR_SLICES: u32 = 65;
pub type Secp256r1 = BigCurve<BigNum<3, 256, Secp256r1_Fq_Params>, Secp256r1_Params>;
pub type Secp256r1Scalar = ScalarField<SECP256r1_SCALAR_SLICES>;
pub type Secp256r1Fq = BigNum<3, 256, Secp256r1_Fq_Params>;
pub type Secp256r1Fr = BigNum<3, 256, Secp256r1_Fr_Params>;

