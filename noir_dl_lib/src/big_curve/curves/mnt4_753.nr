use crate::bignum::BigNum;
use crate::bignum::fields::mnt4_753Fq::MNT4_753_Fq_Params;
use crate::bignum::fields::mnt4_753Fr::MNT4_753_Fr_Params;
use crate::big_curve::CurveParamsTrait;
use crate::big_curve::BigCurve;
use crate::big_curve::scalar_field::ScalarField;

global MNT4_753_SCALAR_SLICES: u32 = 189;
pub struct MNT4_753_Params {}
impl CurveParamsTrait<BigNum<7, 753, MNT4_753_Fq_Params>> for MNT4_753_Params {
    fn a() -> BigNum<7, 753, MNT4_753_Fq_Params> {
        BigNum { limbs: [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] }
    }
    fn b() -> BigNum<7, 753, MNT4_753_Fq_Params> {
        BigNum {
            limbs: [
                0xad265458e06372009c9a0491678ef4,
                0x773111c36c8b1b4e8f1ece940ef9ea,
                0xc3d8bb21c8d68bb8cfb9db4b8c8fba,
                0xa92c78dc537e51a16703ec9855c77f,
                0x051c596560835df0c9e50a5b59b882,
                0xc9dcae7a016ac5d7748d3313cd8e39,
                0x01373684a8,
            ],
        }
    }
    fn one() -> [BigNum<7, 753, MNT4_753_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [
                    0xc2ab23be1c24740af0fdeb3b7f1981,
                    0xfeff338dd73a5a7eeecfbce7cf95d3,
                    0x463d98a4ea009d57aad9716f708885,
                    0x6d1ef781d1de4ffb1f806b314c5ad3,
                    0xefa5546444d40c82d6a271f1a43862,
                    0x450bb76a02d86daaffbaeb69995eb9,
                    0x542f1dad,
                ],
            },
            BigNum {
                limbs: [
                    0x031ea99cff05e05ec3be2e4a050358,
                    0x23036db8fb990a342449caeb92fa6b,
                    0x5dea57ef53ee29157bdf1b741aebd4,
                    0xee5599dd7c3dfa4100284833115aec,
                    0x7fddcdea19cb10b2bf61f37ae2c456,
                    0x26e257b175ae94deb9e10aba4ba72f,
                    0x4ab64735,
                ],
            },
        ]
    }
    fn offset_generator() -> [BigNum<7, 753, MNT4_753_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [
                    0x626a3f756e21d88542b02626edba28,
                    0x4e5fcb24def435b831b168d03ffa17,
                    0x37176e9c4f71cf8b3d7dd158ff79d6,
                    0x02a27192bd63ff0ae75b427f371e0f,
                    0x19d7d1a5ec40d8c9e958c8ff2851b5,
                    0x4f67020973b5ef46536489d2168c1d,
                    0x0165cd5cb7,
                ],
            },
            BigNum {
                limbs: [
                    0xa30942007a5fd26683b2666547b8ac,
                    0x2b81278933c31d48aedf581d9cc73f,
                    0xd4a7583126a808f4f6b39b9fab6392,
                    0x6dd10e9d210364c99c4313dc900447,
                    0xff95481ef076765ab79c10181db9d9,
                    0x524ad0a6e34b47375458acac5dfb50,
                    0xd39ff56b,
                ],
            },
        ]
    }
    fn offset_generator_final() -> [BigNum<7, 753, MNT4_753_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [
                    0xa58e0356b1875bb057efadc335d7ef,
                    0xf9f6bb7070e70c1f52aa90c2eea40b,
                    0x79f3748370ac445ba29c746935278f,
                    0x2583c367ac3bf38902abcbd7d1f96b,
                    0xb0d541577618ab033e51c0197e9892,
                    0xa1defaff53c883c79edd0f16db9cb7,
                    0x976315b5,
                ],
            },
            BigNum {
                limbs: [
                    0x09a86892894b8aa69ee96bf1fc249e,
                    0x53fe404e91c85ad0f982aa10a9d9d8,
                    0x424af093cf222be97190fecb7e9f8b,
                    0x63e2ab17ef6aa3fb2db6bed30f61f0,
                    0x7e39a85475a73215ab0576a69ab318,
                    0x87258dcaaec7d994b10b88828830c5,
                    0x01215baa38,
                ],
            },
        ]
    }
}

pub type MNT4_753 = BigCurve<BigNum<7, 753, MNT4_753_Fq_Params>, MNT4_753_Params>;
pub type MNT4_753Scalar = ScalarField<MNT4_753_SCALAR_SLICES>;
pub type MNT4_753Fq = BigNum<7, 753, MNT4_753_Fq_Params>;
pub type MNT4_753Fr = BigNum<7, 753, MNT4_753_Fr_Params>;

