use bignum::params::BigNumParams;
use bignum::params::BigNumParamsGetter;
use bignum::bignum::BigNum;

pub struct Secp521r1_Fq_Params {}

impl BigNumParamsGetter<5, 521> for Secp521r1_Fq_Params {
    fn get_params() -> BigNumParams<5, 521> {
        Secp521r1_Fq_PARAMS
    }
}

global Secp521r1_Fq_PARAMS: BigNumParams<5, 521> = BigNumParams::new(
    true,
    [
        0xffffffffffffffffffffffffffffff,
        0xffffffffffffffffffffffffffffff,
        0xffffffffffffffffffffffffffffff,
        0xffffffffffffffffffffffffffffff,
        0x01ffffffffff,
    ],
    [0x10, 0x0, 0x0, 0x0, 0x200000000000],
);

pub struct Secp521r1_Fr_Params {}

impl BigNumParamsGetter<5, 521> for Secp521r1_Fr_Params {
    fn get_params() -> BigNumParams<5, 521> {
        Secp521r1_Fr_PARAMS
    }
}

global Secp521r1_Fr_PARAMS: BigNumParams<5, 521> = BigNumParams::new(
    true,
    [
        0xb5c9b8899c47aebb6fb71e91386409,
        0x8783bf2f966b7fcc0148f709a5d03b,
        0xfffffffffffffffffffffffffa5186,
        0xffffffffffffffffffffffffffffff,
        0x01ffffffffff,
    ],
    [
        0xa36477663b851449048e16ec79bf70,
        0x87c40d069948033feb708f65a2fc44,
        0x5ae797,
        0x0,
        0x200000000000,
    ],
);

pub type Secp521r1Fq = BigNum<5, 521, Secp521r1_Fq_Params>;
pub type Secp521r1Fr = BigNum<5, 521, Secp521r1_Fr_Params>;
