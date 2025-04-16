use crate::bignum::BigNum;
use super::params::BrainpoolP256t1_Fq_Params;
use crate::big_curve::CurveParamsTrait;

global BRAINPOOLP256t1_SCALAR_SLICES: u32 = 65;
pub struct BrainpoolP256t1_Params {}
impl CurveParamsTrait<BigNum<3, 256, BrainpoolP256t1_Fq_Params>> for BrainpoolP256t1_Params {
    fn a() -> BigNum<3, 256, BrainpoolP256t1_Fq_Params> {
        BigNum {
            limbs: [0x3bf623d52620282013481d1f6e5374, 0x57dba1eea9bc3e660a909d838d726e, 0xa9fb],
        }
    }
    fn b() -> BigNum<3, 256, BrainpoolP256t1_Fq_Params> {
        BigNum {
            limbs: { [0x93ebc4af2f49256ae58101fee92b04, 0x61c430d84ea4fe66a7733d0b76b7bf, 0x662c] },
        }
    }

    fn offset_generator() -> [BigNum<3, 256, BrainpoolP256t1_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [0xdf7b7690a146dc4daa3e512094cd28, 0x0293f430def68c091076b5e85608a3, 0x256a],
            },
            BigNum {
                limbs: [0x3cd2eb3fdb4d801d7d357371eeb0f7, 0xaa3d8b3084d3a11df020a3fe22a258, 0x4ecd],
            },
        ]
    }

    fn offset_generator_final() -> [BigNum<3, 256, BrainpoolP256t1_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [0x982c0658a8aa105afe1c74b5f403b5, 0x7b8ade1081f0492e3fab6d9a99d0c2, 0x7dcf],
            },
            BigNum {
                limbs: [0x442f5f8f9bdef5a5366dc979b93d2a, 0xd1c8259ef3e220a6792624929c0520, 0x4862],
            },
        ]
    }

    fn one() -> [BigNum<3, 256, BrainpoolP256t1_Fq_Params>; 2] {
        [
            BigNum {
                limbs: {
                    [0xa142c47aafbc2b79a191562e1305f4, 0xeb3cc1cfe7b7732213b23a656149af, 0xa3e8]
                },
            },
            BigNum {
                limbs: {
                    [0xbcb6de39d027001dabe8f35b25c9be, 0x6c823439c56d7f7b22e14644417e69, 0x2d99]
                },
            },
        ]
    }
}
