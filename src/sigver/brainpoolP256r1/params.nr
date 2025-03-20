use bignum::params::BigNumParams;
use bignum::params::BigNumParamsGetter;
use bignum::bignum::BigNum;

pub struct BrainpoolP256r1_Fq_Params {}

impl BigNumParamsGetter<3, 256> for BrainpoolP256r1_Fq_Params {
    fn get_params() -> BigNumParams<3, 256> {
        BrainpoolP256r1_Fq_PARAMS
    }
}

global BrainpoolP256r1_Fq_PARAMS: BigNumParams<3, 256> = BigNumParams::new(
    true,
    [0x3bf623d52620282013481d1f6e5377, 0x57dba1eea9bc3e660a909d838d726e, 0xa9fb],
    [0xf54a0ff6a2fa9b62ae6301180dd0c0, 0x131a1c55b7ebb73aba8322a7bf29b4, 0x1818c1],
);

pub struct BrainpoolP256r1_Fr_Params {}

impl BigNumParamsGetter<3, 256> for BrainpoolP256r1_Fr_Params {
    fn get_params() -> BigNumParams<3, 256> {
        BrainpoolP256r1_Fr_PARAMS
    }
}

global BrainpoolP256r1_Fr_PARAMS: BigNumParams<3, 256> = BigNumParams::new(
    true,
    [0x397aa3b561a6f7901e0e82974856a7, 0x57dba1eea9bc3e660a909d838d718c, 0xa9fb],
    [0x88c5fdf55ea50d73b46ccd107160, 0x131a1c55b7ebb73aba8322a7bf49bf, 0x1818c1],
);

pub type BrainpoolP256r1Fq = BigNum<3, 256, BrainpoolP256r1_Fq_Params>;
pub type BrainpoolP256r1Fr = BigNum<3, 256, BrainpoolP256r1_Fr_Params>;
