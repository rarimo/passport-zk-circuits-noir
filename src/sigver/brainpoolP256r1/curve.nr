use crate::bignum::BigNum;
use super::params::BrainpoolP256r1_Fq_Params;
use crate::big_curve::CurveParamsTrait;

global BRAINPOOLP256R1_SCALAR_SLICES: u32 = 65;
pub struct BrainpoolP256r1_Params {}
impl CurveParamsTrait<BigNum<3, 256, BrainpoolP256r1_Fq_Params>> for BrainpoolP256r1_Params {
    fn a() -> BigNum<3, 256, BrainpoolP256r1_Fq_Params> {
        BigNum {
            limbs: [0x8055c126dc5c6ce94a4b44f330b5d9, 0x975fc2c3057eef67530417affe7fb, 0x7d5a],
        }
    }
    fn b() -> BigNum<3, 256, BrainpoolP256r1_Fq_Params> {
        BigNum {
            limbs: { [0x8416295cf7e1ce6bccdc18ff8c07b6, 0x5c6ce94a4b44f330b5d9bbd77cbf95, 0x26dc] },
        }
    }

    fn offset_generator() -> [BigNum<3, 256, BrainpoolP256r1_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [0xdf7b7690a146dc4daa3e512094cd28, 0x0293f430def68c091076b5e85608a3, 0x256a],
            },
            BigNum {
                limbs: [0xe90d38a99e804a5d800451dcb0103e, 0x398ffd08546ea665948bc7f6fb6ca7, 0x0b5e],
            },
        ]
    }

    fn offset_generator_final() -> [BigNum<3, 256, BrainpoolP256r1_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [0xa92997c4eee759bbff34df47c83551, 0x49c4a27c8f3a09dce7819cd9e8903d, 0x8bd1],
            },
            BigNum {
                limbs: [0x7c95e35a05c9ad107623858de9a569, 0x9fd7b0ea3a97ed1cd0b8820e3aec6d, 0x26e5],
            },
        ]
    }

    fn one() -> [BigNum<3, 256, BrainpoolP256r1_Fq_Params>; 2] {
        [
            BigNum {
                limbs: {
                    [0xde27e1e3bd23c23a4453bd9ace3262, 0xaeb9cb7e57cb2c4b482ffc81b7afb9, 0x8bd2]
                },
            },
            BigNum {
                limbs: {
                    [0x7745132ded8e545c1d54c72f046997, 0xf835c3dac4fd97f8461a14611dc9c2, 0x547e]
                },
            },
        ]
    }
}
