use crate::bignum::BigNumTrait;
use crate::bignum::bignum::BigNum;
use crate::big_curve::CurveParamsTrait;
use crate::big_curve::BigCurve;
use crate::big_curve::curve_jac::CurveJ;

use crate::sigver::secp521r1::params::Secp521r1_Fq_Params;
use crate::sigver::secp521r1::curve::Secp521r1_Params;

use crate::bignum::fields::secp384r1Fq::Secp384r1_Fq_Params;

use crate::sigver::brainpoolP256r1::params::BrainpoolP256r1_Fq_Params;
use crate::sigver::brainpoolP256r1::curve::BrainpoolP256r1_Params;

use crate::sigver::brainpoolP256t1::params::BrainpoolP256t1_Fq_Params;
use crate::sigver::brainpoolP256t1::curve::BrainpoolP256t1_Params;

use crate::sigver::brainpoolP384r1::params::BrainpoolP384r1_Fq_Params;
use crate::sigver::brainpoolP384r1::curve::BrainpoolP384r1_Params;

use crate::sigver::brainpoolP384t1::params::BrainpoolP384t1_Fq_Params;
use crate::sigver::brainpoolP384t1::curve::BrainpoolP384t1_Params;

use crate::sigver::brainpoolP512r1::params::BrainpoolP512r1_Fq_Params;
use crate::sigver::brainpoolP512r1::curve::BrainpoolP512r1_Params;

use crate::sigver::brainpoolP512t1::params::BrainpoolP512t1_Fq_Params;
use crate::sigver::brainpoolP512t1::curve::BrainpoolP512t1_Params;

type BrainpoolP256r1BN = BigNum<3, 256, BrainpoolP256r1_Fq_Params>;
type BrainpoolP256t1BN = BigNum<3, 256, BrainpoolP256t1_Fq_Params>;
type BrainpoolP384r1BN = BigNum<4, 384, BrainpoolP384r1_Fq_Params>;
type BrainpoolP384t1BN = BigNum<4, 384, BrainpoolP384t1_Fq_Params>;
type BrainpoolP512r1BN = BigNum<5, 512, BrainpoolP512r1_Fq_Params>;
type BrainpoolP512t1BN = BigNum<5, 512, BrainpoolP512t1_Fq_Params>;
type Secp521r1BN = BigNum<5, 521, Secp521r1_Fq_Params>;
type Secp384r1BN = BigNum<4, 384, Secp384r1_Fq_Params>;

// from: https://github.com/noir-lang/noir_bigcurve/blob/main/src/utils/hash_to_curve.nr
unconstrained fn compute_and_print_offset_generators<Fq, Curve, let K: u32, let J: u32, let NScalarSlices: u32>(
    n: u32,
    paramstr: str<K>,
    curvestr: str<J>,
    cofactor: Field,
)
where
    Fq: BigNumTrait + std::ops::Mul + std::ops::Add + std::cmp::Eq,
    Curve: CurveParamsTrait<Fq>,
{
    let a = Curve::a();
    let b = Curve::b();

    let one = Curve::one();

    let input: BigCurve<Fq, Curve> = BigCurve::one();
    input.validate_on_curve();

    let seed: [u8; 25] = "bigcurve offset generator".as_bytes();

    // we only need well-defined parameters for a and b, for hash_to_curve to work
    // (no offset gneerators needed)
    let g: BigCurve<Fq, Curve> = BigCurve::hash_to_curve(seed);

    let g_init: CurveJ<Fq, Curve> = CurveJ { x: g.x, y: g.y, z: Fq::one(), is_infinity: false };
    let mut gen = g_init;

    let cofactor_bits: [u1; 128] = cofactor.to_be_bits();
    let mut it: u32 = 0;
    for i in 0..128 {
        if (cofactor_bits[i] == 1) {
            it = i + 1;
            break;
        }
    }

    for i in it..128 {
        gen = gen.dbl().0;
        if (cofactor_bits[i] == 1) {
            gen = gen.incomplete_add(g_init).0;
        }
    }

    let mut offset_generator_initial: [Fq; 2] = [Fq::new(); 2];
    let mut offset_generator_final: [Fq; 2] = [Fq::new(); 2];

    {
        let mut genz = gen.z;
        genz = genz.__invmod();
        let zz = genz.__mul(genz);
        let zzz = zz.__mul(genz);

        offset_generator_initial[0] = gen.x.__mul(zz);
        offset_generator_initial[1] = gen.y.__mul(zzz);
    }

    let end = (NScalarSlices - 1) * 4;
    for _ in 0..end {
        gen = gen.dbl().0;
    }
    {
        let mut genz = gen.z;
        genz = genz.__invmod();
        let zz = genz.__mul(genz);
        let zzz = zz.__mul(genz);

        offset_generator_final[0] = gen.x.__mul(zz);
        offset_generator_final[1] = gen.y.__mul(zzz);
    }
}

#[test]
fn offset_generator() {
    unsafe {
        // compute_and_print_offset_generators::<Secp521r1BN, Secp521r1_Params, _, _, 131>(
        //     5,
        //     "Secp521r1_Fq_Params",
        //     "Secp521r1_Params",
        //     1,
        // );
        // compute_and_print_offset_generators::<BrainpoolP256r1BN, BrainpoolP256r1_Params, _, _, 65>(
        //     3,
        //     "BrainpoolP256r1_Fq_Params",
        //     "BrainpoolP256r1_Params",
        //     1,
        // );
        // compute_and_print_offset_generators::<BrainpoolP256t1BN, BrainpoolP256t1_Params, _, _, 65>(
        //     3,
        //     "BrainpoolP256t1_Fq_Params",
        //     "BrainpoolP256t1_Params",
        //     1,
        // );
        // compute_and_print_offset_generators::<BrainpoolP384r1BN, BrainpoolP384r1_Params, _, _, 97>(
        //     4,
        //     "BrainpoolP384r1_Fq_Params",
        //     "BrainpoolP384r1_Params",
        //     1,
        // );
        // compute_and_print_offset_generators::<BrainpoolP384t1BN, BrainpoolP384t1_Params, _, _, 97>(
        //     4,
        //     "BrainpoolP384t1_Fq_Params",
        //     "BrainpoolP384t1_Params",
        //     1,
        // );
        // compute_and_print_offset_generators::<BrainpoolP512r1BN, BrainpoolP512r1_Params, _, _, 129>(
        //     5,
        //     "BrainpoolP512r1_Fq_Params",
        //     "BrainpoolP512r1_Params",
        //     1,
        // );
        compute_and_print_offset_generators::<BrainpoolP512t1BN, BrainpoolP512t1_Params, _, _, 129>(
            5,
            "BrainpoolP512t1_Fq_Params",
            "BrainpoolP512t1_Params",
            1,
        );
        // compute_and_print_offset_generators::<Secp384r1BN, Secp384r1PartialCurveParams, _, _, 97>(
        //     4,
        //     "Secp384r1_Fq_Params",
        //     "Secp384r1_Params",
        //     1,
        // );
    }
}
