use bignum::params::BigNumParams;
use bignum::params::BigNumParamsGetter;
use bignum::bignum::BigNum;

pub struct BrainpoolP384t1_Fq_Params {}

impl BigNumParamsGetter<4, 384> for BrainpoolP384t1_Fq_Params {
    fn get_params() -> BigNumParams<4, 384> {
        BrainpoolP384t1_Fq_PARAMS
    }
}

global BrainpoolP384t1_Fq_PARAMS: BigNumParams<4, 384> = BigNumParams::new(
    true,
    [
        0xd3a729901d1a71874700133107ec53,
        0x7109ed5456b412b1da197fb71123ac,
        0x82a3386d280f5d6f7e50e641df152f,
        0x8cb91e,
    ],
    [
        0x7bce07a71566f10a03bf684a267160,
        0x449cae56ede9ed590cef1c4d721904,
        0x16d8ec6b8ff25adfd3cc6fa65dda2c,
        0x1d1b575b,
    ],
);

pub struct BrainpoolP384t1_Fr_Params {}

impl BigNumParamsGetter<4, 384> for BrainpoolP384t1_Fr_Params {
    fn get_params() -> BigNumParams<4, 384> {
        BrainpoolP384t1_Fr_PARAMS
    }
}

global BrainpoolP384t1_Fr_PARAMS: BigNumParams<4, 384> = BigNumParams::new(
    true,
    [
        0x3ab6af6b7fc3103b883202e9046565,
        0x7109ed5456b31f166e6cac0425a7cf,
        0x82a3386d280f5d6f7e50e641df152f,
        0x8cb91e,
    ],
    [
        0xfdb467a652109600adcccf8a71f8a0,
        0x449cae56ee1c506f2fe165031e7189,
        0x16d8ec6b8ff25adfd3cc6fa65dda2c,
        0x1d1b575b,
    ],
);

pub type BrainpoolP384t1Fq = BigNum<4, 384, BrainpoolP384t1_Fq_Params>;
pub type BrainpoolP384t1Fr = BigNum<4, 384, BrainpoolP384t1_Fr_Params>;
