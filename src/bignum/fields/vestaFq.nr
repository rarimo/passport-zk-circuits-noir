//! Blurb sourced from https://github.com/arkworks-rs
//! This library implements the base field of the prime-order curve Vesta, generated by
//! [Daira Hopwood](https://github.com/zcash/pasta). The main feature of this
//! curve is that it forms a cycle with Pallas, i.e. its scalar field and base
//! field respectively are the base field and scalar field of Pallas.
//!
//!
//! Curve information:
//! Vesta:
//! * Base field: q =
//!   28948022309329048855892746252171976963363056481941647379679742748393362948097
//! * Scalar field: r =
//!   28948022309329048855892746252171976963363056481941560715954676764349967630337
//! * Curve equation: y^2 = x^3 + 5
//! * Valuation(q - 1, 2) = 32
//! * Valuation(r - 1, 2) = 32
use crate::bignum::params::BigNumParams;
use crate::bignum::params::BigNumParamsGetter;
use crate::bignum::utils::u60_representation::U60Repr;

pub struct Vesta_Fq_Params {}

impl BigNumParamsGetter<3, 255> for Vesta_Fq_Params {
    fn get_params() -> BigNumParams<3, 255> {
        Vesta_Fq_PARAMS
    }
}

global Vesta_Fq_PARAMS: BigNumParams<3, 255> = BigNumParams {
    has_multiplicative_inverse: true,
    modulus: [0x4698fc0994a8dd8c46eb2100000001, 0x22, 0x4000],
    double_modulus: [
        0x018d31f8132951bb188dd64200000002,
        0x01000000000000000000000000000043,
        0x7fff,
    ],
    modulus_u60: U60Repr {
        limbs: [0x0c46eb2100000001, 0x04698fc0994a8dd8, 0x22, 0x00, 0x4000, 0x00],
    },
    modulus_u60_x4: U60Repr {
        limbs: [
            0x0c46eb2100000001,
            0x04698fc0994a8dd8,
            0x22,
            0x00,
            0x4000,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ],
    },
    redc_param: [0x59c0fd9ad5c89cee4537bfffffffc4, 0xfffffffffffffffffffffffffff76e, 0x0fffff],
};
