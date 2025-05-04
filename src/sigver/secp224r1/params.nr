use crate::bignum::params::BigNumParams;
use crate::bignum::params::BigNumParamsGetter;
use crate::bignum::bignum::BigNum;

pub struct Secp224r1_Fq_Params {}

impl BigNumParamsGetter<2, 224> for Secp224r1_Fq_Params {
    fn get_params() -> BigNumParams<2, 224> {
        Secp224r1_Fq_PARAMS
    }
}

global Secp224r1_Fq_PARAMS: BigNumParams<2, 224> = BigNumParams::new(
    true,
    [0xffffff000000000000000000000001, 0xffffffffffffffffffffffffff], 
    [0xffffffffffffffffffffffff1, 0x1000000000000000000000000000]
);

pub struct Secp224r1_Fr_Params {}

impl BigNumParamsGetter<2, 224> for Secp224r1_Fr_Params {
    fn get_params() -> BigNumParams<2, 224> {
        Secp224r1_Fr_PARAMS
    }
}

global Secp224r1_Fr_PARAMS: BigNumParams<2, 224> = BigNumParams::new(
    true,
    [0xff16a2e0b8f03e13dd29455c5c2a3d, 0xffffffffffffffffffffffffff], 
    [0xe95d1f470fc1ec22d6baa3a3d5c3d, 0x1000000000000000000000000000]
);

pub type Secp224r1Fq = BigNum<2, 224, Secp224r1_Fq_Params>;
pub type Secp224r1Fr = BigNum<2, 224, Secp224r1_Fr_Params>;
