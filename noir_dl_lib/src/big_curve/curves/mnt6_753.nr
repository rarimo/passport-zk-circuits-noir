use crate::bignum::BigNum;
use crate::bignum::fields::mnt6_753Fq::MNT6_753_Fq_Params;
use crate::bignum::fields::mnt6_753Fr::MNT6_753_Fr_Params;
use crate::big_curve::CurveParamsTrait;
use crate::big_curve::BigCurve;
use crate::big_curve::scalar_field::ScalarField;

global MNT6_753_SCALAR_SLICES: u32 = 189;
pub struct MNT6_753_Params {}
impl CurveParamsTrait<BigNum<7, 753, MNT6_753_Fq_Params>> for MNT6_753_Params {
    fn a() -> BigNum<7, 753, MNT6_753_Fq_Params> {
        BigNum { limbs: [0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] }
    }
    fn b() -> BigNum<7, 753, MNT6_753_Fq_Params> {
        BigNum {
            limbs: [
                0xba7505ba6fcf2485540b13dfc8468a,
                0xf9a80a95f401867c4e80f4747fde5a,
                0x0fcf2c43d7bf847957c34cca1e3585,
                0xb7985993f62f03b22a9a3c737a1a1e,
                0xbb64b2bb01b10e60a5d5dfe0a25714,
                0x0863c79d56446237ce2e1468d14ae9,
                0x7da285e7,
            ],
        }
    }
    fn one() -> [BigNum<7, 753, MNT6_753_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [
                    0x329a6fefa9a1f3f7a1fbd93a7bffb8,
                    0x1acbf7da60895b8b3d9d442c4c4123,
                    0xe5e3c57b6df120cee3cd9d867e66d1,
                    0x0c0d5fc5e818771b931f1d5bdd069c,
                    0x131c2437e884c4997fd1dcb409367d,
                    0x6e831147412cfb1002284f30338088,
                    0x255f8e87,
                ],
            },
            BigNum {
                limbs: [
                    0x521df9855687139f0c51754c0ccc49,
                    0x4d9992f5cbf4b2cc4c42eff9a5a6c4,
                    0x0dc7a593cce5a792e94d0020c335b7,
                    0x4c7a18ed9c4bd3c7ed0ffb31c57e61,
                    0x2a3585bdd6d7722c6c07d7873bb02d,
                    0x6e2eb3fca70dc1063bac3455180120,
                    0x0128c02fff,
                ],
            },
        ]
    }
    fn offset_generator() -> [BigNum<7, 753, MNT6_753_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [
                    0xbb4565362dd76213944028a2a0e5ea,
                    0xfed0b9b23c677643d8db909425432b,
                    0x25b23be14aab3c446c44c012ec7050,
                    0x3049e8844b5e37006d0684f0f9579a,
                    0x0aabcf62121623ec2ac0a16c581755,
                    0xbf7cf3e3f525f8526e24d643d064b6,
                    0x0167e7d28f,
                ],
            },
            BigNum {
                limbs: [
                    0x0c8c53994efc3a69348f0a7d870a94,
                    0xc74050c9446ac84b471bdfdb879bc9,
                    0x2e42983e32c0ca65bab6e0f78b6771,
                    0x4f88b5a3027c83bbed00a6ee180197,
                    0xd62eaaa6ef628d6e8a422176080efb,
                    0x47c818f5714e899c83a6d54893f252,
                    0x011008d2e6,
                ],
            },
        ]
    }
    fn offset_generator_final() -> [BigNum<7, 753, MNT6_753_Fq_Params>; 2] {
        [
            BigNum {
                limbs: [
                    0x5b6ad7b65e3a86239c2efbdb300b8d,
                    0x7d06f1a94609f8e4eb48c998d1571d,
                    0x95a74f11f2fb5be7544da5c184e38d,
                    0x600f8f2fdcd5e802342ebe03c3787f,
                    0xc3fa8f3f017c7aed50e1a14b78f3b3,
                    0xe7f3b2638fa13f65670c15eb006e99,
                    0x016389a6fb,
                ],
            },
            BigNum {
                limbs: [
                    0x42eb137506b02f7665ebbe0211b768,
                    0x814148c3996475176b11c4db1d356a,
                    0xf97e6cd350259b5456471a2237553f,
                    0x5c822035f3f7c21fc2e6f9aac5945a,
                    0xa319d0923fc0ac9db23b819dcb7371,
                    0xa4186459f74d57db479c998a5db03a,
                    0x7f824db1,
                ],
            },
        ]
    }
}

pub type MNT6_753 = BigCurve<BigNum<7, 753, MNT6_753_Fq_Params>, MNT6_753_Params>;
pub type MNT6_753Scalar = ScalarField<MNT6_753_SCALAR_SLICES>;
pub type MNT6_753Fq = BigNum<7, 753, MNT6_753_Fq_Params>;
pub type MNT6_753Fr = BigNum<7, 753, MNT6_753_Fr_Params>;


