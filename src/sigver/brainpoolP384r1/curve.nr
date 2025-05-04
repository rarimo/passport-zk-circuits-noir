use crate::bignum::BigNum;
use super::params::BrainpoolP384r1_Fq_Params;
use crate::big_curve::CurveParamsTrait;

global BRAINPOOLP384R1_SCALAR_SLICES: u32 = 97;
pub struct BrainpoolP384r1_Params {}
impl CurveParamsTrait<BigNum<4, 384, BrainpoolP384r1_Fq_Params>> for BrainpoolP384r1_Params {
    fn a() -> BigNum<4, 384, BrainpoolP384r1_Fq_Params> {
        BigNum {
            limbs: [
                0xa5814a503ad4eb04a8c7dd22ce2826,
                0xa28e4fb22787139165efba91f90f8a,
                0xc63d8c150c3c72080ace05afa0c2be,
                0x7bc382,
            ],
        }
    }
    fn b() -> BigNum<4, 384, BrainpoolP384r1_Fq_Params> {
        BigNum {
            limbs: {
                [
                    0xb4390295dbc9943ab78696fa504c11,
                    0x7de107dcd2a62e880ea53eeb62d57c,
                    0xdd22ce28268b39b55416f0447c2fb7,
                    0x4a8c7,
                ]
            },
        }
    }

    fn offset_generator() -> [BigNum<4, 384, BrainpoolP384r1_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [
                    0xbbbaabfc4cac1a405d106d80d5c4d3,
                    0x43fd3007a1f13a542923edd0092e31,
                    0x56f1e610db6c0448cd751930f2aec1,
                    0x6bfeb1,
                ],
            },
            BigNum {
                limbs: [
                    0xc9c86458b6cea4b5b0de7915d7bbae,
                    0xac24a6ee83c6a3f28782753877c208,
                    0xeaa52b8f5dd6e1e0f1d1f7bebdcbb2,
                    0x3837d0,
                ],
            },
        ]
    }

    fn offset_generator_final() -> [BigNum<4, 384, BrainpoolP384r1_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [
                    0x2e9f7227713bea6f733c401324b4e0,
                    0x785e76d88efb112077932d55a977da,
                    0xa0a30affcd27bceca918db80e34dd6,
                    0x1bce71,
                ],
            },
            BigNum {
                limbs: [
                    0x5be84d2eeb67a7c229a9fa69e4b8fe,
                    0xbfe86c50b839a1fd240ccd06d5c2e6,
                    0xc93d3f8b990b154369ebf7c3621a8d,
                    0x60cef5,
                ],
            },
        ]
    }

    fn one() -> [BigNum<4, 384, BrainpoolP384r1_Fq_Params>; 2] {
        [
            BigNum {
                limbs: {
                    [
                        0x26e03436d646aaef87b2e247d4af1e,
                        0xa3e77ef14fe3db7fcafe0cbd10e8e8,
                        0xf068cf45ffa2a63a81b7c13f6b8847,
                        0x1d1c64,
                    ]
                },
            },
            BigNum {
                limbs: {
                    [
                        0x4646217791811142820341263c5315,
                        0xb29feec5864e19c054ff99129280e,
                        0x7520f9c2a45cb1eb8e95cfd55262b7,
                        0x8abe1d,
                    ]
                },
            },
        ]
    }
}
