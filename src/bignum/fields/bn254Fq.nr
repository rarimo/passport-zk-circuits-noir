use crate::bignum::params::BigNumParams;
use crate::bignum::params::BigNumParamsGetter;
use crate::bignum::utils::u60_representation::U60Repr;

pub struct BN254_Fq_Params {}

impl BigNumParamsGetter<3, 254> for BN254_Fq_Params {
    fn get_params() -> BigNumParams<3, 254> {
        BN254_Fq_PARAMS
    }
}

global BN254_Fq_PARAMS: BigNumParams<3, 254> = BigNumParams {
    has_multiplicative_inverse: true,
    modulus: [0x816a916871ca8d3c208c16d87cfd47, 0x4e72e131a029b85045b68181585d97, 0x3064],
    double_modulus: [
        0x0102d522d0e3951a7841182db0f9fa8e,
        0x019ce5c263405370a08b6d0302b0bb2e,
        0x60c7,
    ],
    modulus_u60: U60Repr {
        limbs: [
            0x0c208c16d87cfd47,
            0x0816a916871ca8d3,
            0x45b68181585d97,
            0x04e72e131a029b85,
            0x3064,
            0x00,
        ],
    },
    modulus_u60_x4: U60Repr {
        limbs: [
            0x0c208c16d87cfd47,
            0x0816a916871ca8d3,
            0x45b68181585d97,
            0x04e72e131a029b85,
            0x3064,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ],
    },
    redc_param: [0x65e1767cd4c086f3aed8a19bf90e51, 0x462623a04a7ab074a5868073013ae9, 0x054a47],
};
