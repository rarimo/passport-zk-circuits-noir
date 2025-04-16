use super::brainpoolP256r1::params::{BrainpoolP256r1Fq, BrainpoolP256r1Fr};
use super::brainpoolP256r1::curve::BrainpoolP256r1_Params;
use super::brainpoolP256t1::params::{BrainpoolP256t1Fq, BrainpoolP256t1Fr};
use super::brainpoolP256t1::curve::BrainpoolP256t1_Params;
use super::brainpoolP384r1::params::{BrainpoolP384r1Fq, BrainpoolP384r1Fr};
use super::brainpoolP384r1::curve::BrainpoolP384r1_Params;
use super::brainpoolP384t1::params::{BrainpoolP384t1Fq, BrainpoolP384t1Fr};
use super::brainpoolP384t1::curve::BrainpoolP384t1_Params;
use super::brainpoolP512r1::params::{BrainpoolP512r1Fq, BrainpoolP512r1Fr};
use super::brainpoolP512r1::curve::BrainpoolP512r1_Params;
use super::brainpoolP512t1::params::{BrainpoolP512t1Fq, BrainpoolP512t1Fr};
use super::brainpoolP512t1::curve::BrainpoolP512t1_Params;
use crate::sigver::secp521r1::params::{Secp521r1Fq, Secp521r1Fr};
use crate::sigver::secp521r1::curve::{SECP521r1_SCALAR_SLICES, Secp521r1_Params};
use crate::sigver::secp224r1::params::{Secp224r1Fq, Secp224r1Fr};
use crate::sigver::secp224r1::curve::{SECP224r1_SCALAR_SLICES, Secp224r1_Params};
use crate::big_curve::scalar_field::ScalarField;
use crate::big_curve::CurveParamsTrait;
use crate::big_curve::BigCurve;
use crate::bignum::BigNum;
use crate::bignum::params::BigNumParamsGetter;
use crate::big_curve::curves::secp384r1::{Secp384r1Fq, Secp384r1Fr, Secp384r1_Params};
use crate::big_curve::curves::secp256r1::{Secp256r1Fq, Secp256r1Fr, Secp256r1_Params};

// https://github.com/madztheo/noir-ecdsa/blob/main/lib/src/secp384r1.nr
pub fn verify_ecdsa<let HASH_BYTE_SIZE: u32, let SCALAR_SLICES: u32, let LIMBS: u32, let MODULUS_BIT_SIZE: u32, let BYTES: u32, Fq_PARAMS, Fr_PARAMS, CurveParams>(
    public_key_x: BigNum<LIMBS, MODULUS_BIT_SIZE, Fq_PARAMS>,
    public_key_y: BigNum<LIMBS, MODULUS_BIT_SIZE, Fq_PARAMS>,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (BigNum<LIMBS, MODULUS_BIT_SIZE, Fr_PARAMS>, BigNum<LIMBS, MODULUS_BIT_SIZE, Fr_PARAMS>),
) -> bool
where
    Fq_PARAMS: BigNumParamsGetter<LIMBS, MODULUS_BIT_SIZE>,
    Fr_PARAMS: BigNumParamsGetter<LIMBS, MODULUS_BIT_SIZE>,
    CurveParams: CurveParamsTrait<BigNum<LIMBS, MODULUS_BIT_SIZE, Fq_PARAMS>>,
{
    // 1. Unpack the signature (r, s)
    let (r, s) = signature;

    // 2. Pad the message digest to `BYTES` bytes and convert to a BigNum
    let mut formatted_message_digest: [u8; BYTES] = [0; BYTES];
    let mut startIndex = 0;

    if HASH_BYTE_SIZE < BYTES {
        startIndex = BYTES - HASH_BYTE_SIZE;
    }
    for i in startIndex..BYTES {
        formatted_message_digest[i] = message_digest[i - startIndex];
    }
    let e: BigNum<LIMBS, MODULUS_BIT_SIZE, Fr_PARAMS> =
        BigNum::from_be_bytes(formatted_message_digest);

    // 3. Compute w = s^-1 mod n
    let w = s.__invmod();
    // Check that s is the inverse of w since the previous line is unconstrained
    assert(s * w == BigNum::one());

    // 4. Compute u1 = ew mod n and u2 = rw mod n
    let u_1: ScalarField<SCALAR_SLICES> = ScalarField::from_bignum(e * w);
    let u_2: ScalarField<SCALAR_SLICES> = ScalarField::from_bignum(r * w);

    // Convert public key to jacobian coordinates
    let public_key: BigCurve<BigNum<LIMBS, MODULUS_BIT_SIZE, Fq_PARAMS>, CurveParams> =
        BigCurve { x: public_key_x, y: public_key_y, is_infinity: false };
    public_key.validate_on_curve();

    let gen: BigCurve<BigNum<LIMBS, MODULUS_BIT_SIZE, Fq_PARAMS>, CurveParams> = BigCurve::one();

    // 5. Compute the point R = u1G + u2Q
    let r_point = BigCurve::msm([gen, public_key], [u_1, u_2]);

    let r_point_x = r_point.x;
    let r_point_x_as_fr: BigNum<LIMBS, MODULUS_BIT_SIZE, Fr_PARAMS> =
        BigNum { limbs: r_point_x.limbs };
    // 6. The signature is valid if r = R.x (mod n)
    // Need to have them in the same field to do the comparison
    r_point_x_as_fr == r
}

pub fn verify_secp521r1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: Secp521r1Fq,
    public_key_y: Secp521r1Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (Secp521r1Fr, Secp521r1Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 131, _, _, 66, _, _, Secp521r1_Params>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

pub fn verify_secp384r1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: Secp384r1Fq,
    public_key_y: Secp384r1Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (Secp384r1Fr, Secp384r1Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 97, _, _, 48, _, _, Secp384r1_Params>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

pub fn verify_secp256r1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: Secp256r1Fq,
    public_key_y: Secp256r1Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (Secp256r1Fr, Secp256r1Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 65, _, _, 32, _, _, Secp256r1_Params>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

pub fn verify_brainpoolp256r1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: BrainpoolP256r1Fq,
    public_key_y: BrainpoolP256r1Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (BrainpoolP256r1Fr, BrainpoolP256r1Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 65, _, _, 32, _, _, BrainpoolP256r1_Params>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

pub fn verify_brainpoolp256t1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: BrainpoolP256t1Fq,
    public_key_y: BrainpoolP256t1Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (BrainpoolP256t1Fr, BrainpoolP256t1Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 65, _, _, 32, _, _, BrainpoolP256t1_Params>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

pub fn verify_brainpoolp384r1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: BrainpoolP384r1Fq,
    public_key_y: BrainpoolP384r1Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (BrainpoolP384r1Fr, BrainpoolP384r1Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 97, _, _, 48, _, _, BrainpoolP384r1_Params>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

pub fn verify_brainpoolp384t1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: BrainpoolP384t1Fq,
    public_key_y: BrainpoolP384t1Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (BrainpoolP384t1Fr, BrainpoolP384t1Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 97, _, _, 48, _, _, BrainpoolP384t1_Params>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

pub fn verify_brainpoolp512r1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: BrainpoolP512r1Fq,
    public_key_y: BrainpoolP512r1Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (BrainpoolP512r1Fr, BrainpoolP512r1Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 129, _, _, 64, _, _, BrainpoolP512r1_Params>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

pub fn verify_brainpoolp512t1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: BrainpoolP512t1Fq,
    public_key_y: BrainpoolP512t1Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (BrainpoolP512t1Fr, BrainpoolP512t1Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 129, _, _, 64, _, _, BrainpoolP512t1_Params>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

#[test]
fn test_secp521r1_signature_verification() {
    let sha256_hash: [u8; 32] =
        dep::std::hash::sha256("Hello World! This is Noir-ECDSA".as_bytes());
    assert_eq(
        sha256_hash,
        [
            42, 204, 207, 15, 192, 246, 143, 215, 180, 110, 75, 247, 21, 126, 103, 225, 251, 180,
            86, 221, 251, 68, 216, 63, 17, 236, 32, 223, 169, 198, 9, 98,
        ],
    );
    let r: Secp521r1Fr = BigNum {
        limbs: [
            0x5d54ec424d96736a8eb7ab6b38d908,
            0x652b2107a280804afad6f3d2cc0050,
            0xed0e5a379f9fb054d066eb356d254c,
            0xfc86bb58b30a527e65c6f834a6d3db,
            0x4d2cade92f,
        ],
    };
    let s: Secp521r1Fr = BigNum {
        limbs: [
            0xbbbde07f01798860628f5af9dd2a64,
            0x5416a9927335c1e6aae0cf33d44413,
            0xc05b8c91b0f63441f63929b0d065d4,
            0x35905117e2c37f88dcffbd84648d9f,
            0x8412499ba5,
        ],
    };
    let public_key_x: Secp521r1Fq = BigNum {
        limbs: [
            0xe976cfcef3735cd6b59ac2014c4ae3,
            0xbc1c4e1989e7b94f353e9194948ed0,
            0xdea95c2502cfe36a3479a18960cf40,
            0x69b79211e183033c2f123720e96888,
            0x191ceb966f3,
        ],
    };
    let public_key_y: Secp521r1Fq = BigNum {
        limbs: [
            0xe10762c5d5f93c2754f5172fd76a6a,
            0x4d432eaa4382eaaace7018ff2268b,
            0x5e8326529e8b8bcf701c5d29bf70d6,
            0xb494cf3fb13e60d4619a41c13775cd,
            0x1c03b12ef33,
        ],
    };
    assert(verify_secp521r1_ecdsa(public_key_x, public_key_y, sha256_hash, (r, s)));
}

#[test]
fn test_secp384r1_signature_verification() {
    let sha256_hash: [u8; 32] =
        dep::std::hash::sha256("Hello World! This is Noir-ECDSA".as_bytes());
    assert_eq(
        sha256_hash,
        [
            42, 204, 207, 15, 192, 246, 143, 215, 180, 110, 75, 247, 21, 126, 103, 225, 251, 180,
            86, 221, 251, 68, 216, 63, 17, 236, 32, 223, 169, 198, 9, 98,
        ],
    );
    let r: Secp384r1Fr = BigNum {
        limbs: [
            0xeb06adc631cd09d17ed3268f65e288,
            0x4102680df5a59b6fc9f8f38cd01016,
            0x272042bb400a185ba04fefaa7c05ce,
            0x680dc4,
        ],
    };
    let s: Secp384r1Fr = BigNum {
        limbs: [
            0x711084a23ae842fc0e6702c3009784,
            0xe17e64a3c451466091c4c1aae7550f,
            0x017a18c55fc11347e0f27fa8fdb958,
            0x32ec1b,
        ],
    };
    let public_key_x: Secp384r1Fq = BigNum {
        limbs: [
            0x4bb414953ec1391fdbc6ea75e0d61a,
            0xfed1f2c9f9ac404d4bf5c0b267cddb,
            0xd1031dd17188527bc28ade5c97d23c,
            0x41b3d3,
        ],
    };
    let public_key_y: Secp384r1Fq = BigNum {
        limbs: [
            0x23db4726c61ec970c07ff770a2b380,
            0x3270662d9105998b8e26e9575147da,
            0x33e912de6612af790c627629f33de0,
            0x4b834d,
        ],
    };
    assert(verify_secp384r1_ecdsa(public_key_x, public_key_y, sha256_hash, (r, s)));
}

#[test]
fn test_secp256r1_signature_verification() {
    let sha256_hash: [u8; 32] =
        dep::std::hash::sha256("Hello World! This is Noir-ECDSA".as_bytes());
    assert_eq(
        sha256_hash,
        [
            42, 204, 207, 15, 192, 246, 143, 215, 180, 110, 75, 247, 21, 126, 103, 225, 251, 180,
            86, 221, 251, 68, 216, 63, 17, 236, 32, 223, 169, 198, 9, 98,
        ],
    );
    let r: Secp256r1Fr = BigNum {
        limbs: [0x6e6dd8df9cec8c31892d01e14318fb, 0x3109c73f335657be981f6387c44d3c, 0x8e0e],
    };
    let s: Secp256r1Fr = BigNum {
        limbs: [0x262ed99e46e6577a71a75b1d5c7f4a, 0xcefc34f4b68aa019eda376372f2e76, 0x2c2d],
    };
    let public_key_x: Secp256r1Fq = BigNum {
        limbs: [0xd54378ffd74c0a0692ea56dc91e14a, 0xa683ef4c166c55cfb8d135863fc8f9, 0xaa1d],
    };
    let public_key_y: Secp256r1Fq = BigNum {
        limbs: [0x6b6c3604db3440d3dc4ee95a24f0f0, 0xc4eae722e511eeb583122a0f6ab255, 0x4b36],
    };
    assert(verify_secp256r1_ecdsa(public_key_x, public_key_y, sha256_hash, (r, s)));
}

#[test]
fn test_brainpoolp256r1_signature_verification() {
    let sha256_hash: [u8; 32] =
        dep::std::hash::sha256("Hello World! This is Noir-ECDSA".as_bytes());
    assert_eq(
        sha256_hash,
        [
            42, 204, 207, 15, 192, 246, 143, 215, 180, 110, 75, 247, 21, 126, 103, 225, 251, 180,
            86, 221, 251, 68, 216, 63, 17, 236, 32, 223, 169, 198, 9, 98,
        ],
    );

    let r: BrainpoolP256r1Fr = BigNum {
        limbs: [0xb5dbab781aac0d3b9f3363bee44893, 0xc14f36af7f013afc631f5ea41ebaea, 0x70a],
    };

    let s: BrainpoolP256r1Fr = BigNum {
        limbs: [0x829cb95b4418f1b0d1acaa177bb8fb, 0xf536836f61755973c25ba72ec4ae6c, 0x3e5f],
    };

    let public_key_x: BrainpoolP256r1Fq = BigNum {
        limbs: [0x44c2c2f4362c32db014e2d53f81184, 0x73c6514a204b38fccc53e73cee10c8, 0x9c26],
    };

    let public_key_y: BrainpoolP256r1Fq = BigNum {
        limbs: [0x2d297c0cd741b36f47b3305a29536c, 0xb22cccc873db46c4b99f8056ab3afc, 0x895e],
    };

    assert(verify_brainpoolp256r1_ecdsa(public_key_x, public_key_y, sha256_hash, (r, s)));
}

#[test]
fn test_brainpoolp384r1_signature_verification() {
    let sha256_hash: [u8; 32] =
        dep::std::hash::sha256("Hello World! This is Noir-ECDSA".as_bytes());
    assert_eq(
        sha256_hash,
        [
            42, 204, 207, 15, 192, 246, 143, 215, 180, 110, 75, 247, 21, 126, 103, 225, 251, 180,
            86, 221, 251, 68, 216, 63, 17, 236, 32, 223, 169, 198, 9, 98,
        ],
    );

    let r: BrainpoolP384r1Fr = BigNum {
        limbs: [
            0x704089dce05bcb6ce0a9094429d30b,
            0x2707b5a5e61d766b510af6592cc6f0,
            0x7a6a11cf913fea3ab0bb8860ffc5e6,
            0x71dcf0,
        ],
    };

    let s: BrainpoolP384r1Fr = BigNum {
        limbs: [
            0xca44f5b5e489571ed70ffb06f8baca,
            0x878d17ea34066411a8cf39f83016d8,
            0xbc258489da53d75c1bc3263f9a9d13,
            0x845799,
        ],
    };

    let public_key_x: BrainpoolP384r1Fq = BigNum {
        limbs: [
            0x1003f8578f9d68939e218725376b3c,
            0xa3fb7a2aea32dd5fbe8b8834b3bfcd,
            0x4d6cb36e8aa358b5d4a260fccbc385,
            0x3b358f,
        ],
    };

    let public_key_y: BrainpoolP384r1Fq = BigNum {
        limbs: [
            0xdd2e4e62d7c2fa35b26d4bf91af381,
            0x82b9c682c1b8f6345186c166f96a3f,
            0x4295bcb724597af1820d75d3f5c232,
            0x1c529b,
        ],
    };

    assert(verify_brainpoolp384r1_ecdsa(public_key_x, public_key_y, sha256_hash, (r, s)));
}

#[test]
fn test_brainpoolp384t1_signature_verification() {
    let sha256_hash: [u8; 32] =
        dep::std::hash::sha256("Hello World! This is Noir-ECDSA".as_bytes());
    assert_eq(
        sha256_hash,
        [
            42, 204, 207, 15, 192, 246, 143, 215, 180, 110, 75, 247, 21, 126, 103, 225, 251, 180,
            86, 221, 251, 68, 216, 63, 17, 236, 32, 223, 169, 198, 9, 98,
        ],
    );

    let r: BrainpoolP384t1Fr = BigNum {
        limbs: [
            0x71b474f6230c6b1ae4464bbb53fb0,
            0x4c547f4cea0ecda60d4625ae339e17,
            0x91a861c31aeb53350d4361e3838ec3,
            0x176af9,
        ],
    };

    let s: BrainpoolP384t1Fr = BigNum {
        limbs: [
            0x83847bbe454abc8451783c4c116a5c,
            0x37ab01bf9582c3dcc117af5c19ff56,
            0x479633bd14c90b67942b66feb50870,
            0x86606f,
        ],
    };

    let public_key_x: BrainpoolP384t1Fq = BigNum {
        limbs: [
            0x7c9f63fe3b28c5b715596bcb59dbb1,
            0x7eb281300e03d8026c75b6645f323c,
            0xa1960291325d182311b1fd440c69bf,
            0x737bf1,
        ],
    };

    let public_key_y: BrainpoolP384t1Fq = BigNum {
        limbs: [
            0xd4e4c1d55ebbccf88a58deefbace58,
            0x3cdfe92bc0d8d177e6bd8cf53b49c4,
            0xd853d7f2198671df96ffc8aada696d,
            0x1c679f,
        ],
    };

    assert(verify_brainpoolp384t1_ecdsa(public_key_x, public_key_y, sha256_hash, (r, s)));
}

#[test]
fn test_brainpoolp512r1_signature_verification() {
    let sha256_hash: [u8; 32] =
        dep::std::hash::sha256("Hello World! This is Noir-ECDSA".as_bytes());
    assert_eq(
        sha256_hash,
        [
            42, 204, 207, 15, 192, 246, 143, 215, 180, 110, 75, 247, 21, 126, 103, 225, 251, 180,
            86, 221, 251, 68, 216, 63, 17, 236, 32, 223, 169, 198, 9, 98,
        ],
    );

    let r: BrainpoolP512r1Fr = BigNum {
        limbs: [
            0x7a42ee3ff773930fd5a75a5f0f8f44,
            0xe08e9627534dd4b08b51cd50e1ea54,
            0x4b3b4eb9d0c140412ccc7588387e0c,
            0x667c21fe6cdf7a38e9cb665b45cd31,
            0x9c3b9f11,
        ],
    };

    let s: BrainpoolP512r1Fr = BigNum {
        limbs: [
            0x4c0efd3bd4266b117fc777a1ad6451,
            0x3cb8fd090b34989d5fe33955debf93,
            0x6e6cc1d8a6cf561c4f17bbc788b093,
            0x9a726ed28e27cd04c8bfed6f5cdf4,
            0xa93fb2dc,
        ],
    };

    let public_key_x: BrainpoolP512r1Fq = BigNum {
        limbs: [
            0xa84c943bd583159d60859f2cfa0161,
            0x8f6771c6e3495ce6ddad026936d7a6,
            0xdeeca2efdbad740deff518494f590a,
            0x7d4c0f9655b0e3a0fd68d0edaef401,
            0x6c549ffa,
        ],
    };

    let public_key_y: BrainpoolP512r1Fq = BigNum {
        limbs: [
            0x82417399c1673ba45056d27d3e2d0,
            0x66a253b74a0ffa6829acf5ce3a9c8e,
            0xb92617dff6948f4aa6d9b597351d4e,
            0x7509a0b89cd0b7efce6622cedf2796,
            0x840299fc,
        ],
    };

    assert(verify_brainpoolp512r1_ecdsa(public_key_x, public_key_y, sha256_hash, (r, s)));
}

#[test]
fn test_brainpoolp512t1_signature_verification() {
    let sha256_hash: [u8; 32] =
        dep::std::hash::sha256("Hello World! This is Noir-ECDSA".as_bytes());
    assert_eq(
        sha256_hash,
        [
            42, 204, 207, 15, 192, 246, 143, 215, 180, 110, 75, 247, 21, 126, 103, 225, 251, 180,
            86, 221, 251, 68, 216, 63, 17, 236, 32, 223, 169, 198, 9, 98,
        ],
    );

    let r: BrainpoolP512t1Fr = BigNum {
        limbs: [
            0x7746cefc148255fc0469c6c7458167,
            0x9632ecde268968a1f6f171e9ee9cae,
            0x612d682feec3c244e896cec770ecd2,
            0x74ad1958977398b94657a3447d521,
            0x9d977546,
        ],
    };

    let s: BrainpoolP512t1Fr = BigNum {
        limbs: [
            0x651d41325a034561b2af6728f0bfdb,
            0x383fb6406df2c941d2cf71fedb5afc,
            0x1314d72cc11d655778928c6473abfd,
            0x7b1023d78f324c848d45af468846da,
            0x948c0bd9,
        ],
    };

    let public_key_x: BrainpoolP512t1Fq = BigNum {
        limbs: [
            0xdbfb0d9259dcbb574c17a5fd0907d8,
            0x524e5295868b24e8816453980ba46,
            0x1202cdb3acccb9f728cab6032e30a9,
            0xe30c3d06e2ba4dcb1377c310967911,
            0x72408dda,
        ],
    };

    let public_key_y: BrainpoolP512t1Fq = BigNum {
        limbs: [
            0x270944181de6fd04bf119df6d58d54,
            0x438cb67ac1a5f3dfac1a605a567acf,
            0xae972b88bd469b0eacff28204d35be,
            0xc3d429a82ec2c7aebc2d6c1026aa35,
            0x59143171,
        ],
    };

    assert(verify_brainpoolp512t1_ecdsa(public_key_x, public_key_y, sha256_hash, (r, s)));
}
