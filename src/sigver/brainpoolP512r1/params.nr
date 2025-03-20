use bignum::params::BigNumParams;
use bignum::params::BigNumParamsGetter;
use bignum::bignum::BigNum;

pub struct BrainpoolP512r1_Fq_Params {}

impl BigNumParamsGetter<5, 512> for BrainpoolP512r1_Fq_Params {
    fn get_params() -> BigNumParams<5, 512> {
        BrainpoolP512r1_Fq_PARAMS
    }
}

global BrainpoolP512r1_Fq_PARAMS: BigNumParams<5, 512> = BigNumParams::new(
    true,
    [
        0x81ff2f2d82c68528aa6056583a48f3,
        0x9b009bc66842aecda12ae6a380e628,
        0xb3b3c9d20ed6639cca703308717d4d,
        0xdbe9c48b3fd4e6ae33c9fc07cb308d,
        0xaadd9db8,
    ],
    [
        0x621c4603556d117e2cf84e911e8d90,
        0xb38823152c5e47d93034e73ea8c71d,
        0xcc44ef09666ad8f2f5bf92f542ff2,
        0x6daeb8a15d5ea2f03461e1e8373af6,
        0x17f8d7f4ed,
    ],
);

pub struct BrainpoolP512r1_Fr_Params {}

impl BigNumParamsGetter<5, 512> for BrainpoolP512r1_Fr_Params {
    fn get_params() -> BigNumParams<5, 512> {
        BrainpoolP512r1_Fr_PARAMS
    }
}

global BrainpoolP512r1_Fr_PARAMS: BigNumParams<5, 512> = BigNumParams::new(
    true,
    [
        0xb1d381085ddaddb58796829ca90069,
        0x5c414ca92619418661197fac10471d,
        0xb3b3c9d20ed6639cca70330870553e,
        0xdbe9c48b3fd4e6ae33c9fc07cb308d,
        0xaadd9db8,
    ],
    [
        0xf0d9015d5c4ce2fafac64db57db370,
        0xc61a235d449ff38f5f59ee47100ea,
        0xcc44ef09666ad8f2f5bf92f7db947,
        0x6daeb8a15d5ea2f03461e1e8373af6,
        0x17f8d7f4ed,
    ],
);

pub type BrainpoolP512r1Fq = BigNum<5, 512, BrainpoolP512r1_Fq_Params>;
pub type BrainpoolP512r1Fr = BigNum<5, 512, BrainpoolP512r1_Fr_Params>;
