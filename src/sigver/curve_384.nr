use crate::bignum::{BigNum, params::{BigNumParams, BigNumParamsGetter}};


global TWO_POWER_120: Field = 1329227995784915872903807060280344576;

global Brainpool384R1_GENERATOR: [[Field; 4]; 2] = [[0x26e03436d646aaef87b2e247d4af1e, 0xa3e77ef14fe3db7fcafe0cbd10e8e8, 0xf068cf45ffa2a63a81b7c13f6b8847, 0x1d1c64],[0x4646217791811142820341263c5315, 0xb29feec5864e19c054ff99129280e, 0x7520f9c2a45cb1eb8e95cfd55262b7, 0x8abe1d]];

global Brainpool384r1_Fq_PARAMS: BigNumParams<4, 384> = BigNumParams::new(
    true,
    [0xd3a729901d1a71874700133107ec53, 0x7109ed5456b412b1da197fb71123ac, 0x82a3386d280f5d6f7e50e641df152f, 0x8cb91e],
    [0x7bce07a71566f10a03bf684a267166, 0x449cae56ede9ed590cef1c4d721904, 0x16d8ec6b8ff25adfd3cc6fa65dda2c, 0x1d1b575b]
);

pub struct Brainpool384r1_Fq_Params {}

impl BigNumParamsGetter<4, 384> for Brainpool384r1_Fq_Params {
    fn get_params() -> BigNumParams<4, 384> {
        Brainpool384r1_Fq_PARAMS
    }
}

pub struct Brainpool384r1_Fr_Params {}

impl BigNumParamsGetter<4, 384> for Brainpool384r1_Fr_Params {
    fn get_params() -> BigNumParams<4, 384> {
        Brainpool384r1_Fr_PARAMS
    }
}

global Brainpool384r1_Fr_PARAMS: BigNumParams<4, 384> = BigNumParams::new(
    true,
    [0x3ab6af6b7fc3103b883202e9046565, 0x7109ed5456b31f166e6cac0425a7cf, 0x82a3386d280f5d6f7e50e641df152f, 0x8cb91e],
    [0xfdb467a652109600adcccf8a71f8a1, 0x449cae56ee1c506f2fe165031e7189, 0x16d8ec6b8ff25adfd3cc6fa65dda2c, 0x1d1b575b]
);


global a: BigNum<4, 384, Brainpool384r1_Fq_Params> = BigNum {
    limbs: [0xa5814a503ad4eb04a8c7dd22ce2826, 0xa28e4fb22787139165efba91f90f8a, 0xc63d8c150c3c72080ace05afa0c2be, 0x7bc382]
};

global b: BigNum<4, 384, Brainpool384r1_Fq_Params> = BigNum {
    limbs: [0xb4390295dbc9943ab78696fa504c11, 0x7de107dcd2a62e880ea53eeb62d57c, 0xdd22ce28268b39b55416f0447c2fb7, 0x4a8c7]
};

pub fn curve_add(in1: [[Field; 4]; 2], in2: [[Field; 4]; 2]) -> [[Field; 4]; 2]{

    let x1: BigNum<4, 384, Brainpool384r1_Fq_Params> = BigNum {
        limbs: {
            in1[0]
        },
    };

    let y1: BigNum<4, 384, Brainpool384r1_Fq_Params> = BigNum {
        limbs: {
            in1[1]
        },
    };

    let x2: BigNum<4, 384, Brainpool384r1_Fq_Params> = BigNum {
        limbs: {
            in2[0]
        },
    };

    let y2: BigNum<4, 384, Brainpool384r1_Fq_Params> = BigNum {
        limbs: {
            in2[1]
        },
    };

    let lambda = x1
        .__add(x2.__neg())
        .__invmod()
        .__mul(
            y1.add(
                y2.__neg()
                )
            );

    // lambda = (y2 - y1) / (x2 - x1) =>
    // lambda * (x2 - x1) - y2 + y1 === 0
    BigNum::evaluate_quadratic_expression(
            [[lambda]],
            [[false]],
            [[x2, x1]],
            [[false, true]],
            [y2, y1],
            [true, false],
        );

    let x3 = lambda
        .__mul(lambda)
        .__add(
            x1.__neg()
        )
        .__add(
            x2.__neg()
        );
    
    let y3 = lambda
        .__mul(
            x1.__add(
                x3.__neg()
            )
        )
        .__add(
            y1.__neg()
        );

    BigNum::evaluate_quadratic_expression(
        [[lambda]],
        [[false]],
        [[lambda]],
        [[false]],
        [x3, x2, x1],
        [true, true, true],
    );

    BigNum::evaluate_quadratic_expression(
        [[lambda]],
        [[false]],
        [[x3, x1]],
        [[false, true]],
        [y3, y1],
        [false, false],
    );

    [x3.limbs, y3.limbs]
    
}

pub fn curve_double(in1: [[Field; 4]; 2]) -> [[Field; 4]; 2]{
    
    let x1: BigNum<4, 384, Brainpool384r1_Fq_Params> = BigNum {
        limbs: {
            in1[0]
        },
    };

    let y1: BigNum<4, 384, Brainpool384r1_Fq_Params> = BigNum {
        limbs: {
            in1[1]
        },
    };

    let lambda = BigNum::one()
        .__add(
            BigNum::one().__add(BigNum::one())
        )
        .__mul(
            x1.__mul(x1)
        )
        .__add(a)
        .__mul(
            y1.__add(y1)
                .__invmod()
        );

    // -lambda * 2y + 3*x*x + a = 0
    BigNum::evaluate_quadratic_expression(
        [[x1, x1, x1], [y1, y1, BigNum::new()]],
        [[false, false, false], [false, false, false]],
        [[x1], [lambda]],
        [[false], [true]],
        [a],
        [false],
    );

    let x3 = lambda
        .__mul(lambda)
        .__add(
            x1.__add(x1).__neg()
        );
    
    let y3 = lambda
        .__mul(
            x1.__add(x3.__neg())
        )
        .__add(
            y1.__neg()
        );

    BigNum::evaluate_quadratic_expression(
        [[lambda]],
        [[false]],
        [[lambda]],
        [[false]],
        [x3, x1, x1],
        [true, true, true],
    );

    BigNum::evaluate_quadratic_expression(
        [[lambda]],
        [[false]],
        [[x3, x1]],
        [[false, true]],
        [y3, y1],
        [false, false],
    );

    [x3.limbs, y3.limbs]
}

pub fn curve_mult(in1: [[Field; 4];2], scalar: [u1; 384]) -> [[Field; 4]; 2]{
    let scalar_bits: [u1; 384]= scalar;

    let mut res = in1;
    let mut found_first_bit= false;

    for i in 0..384{
        if (found_first_bit){
            res = curve_double(res);
            if (scalar_bits[i] as Field).eq(1){
                res = curve_add(res, in1);
            }
        }
        if ((scalar_bits[i] as Field).eq(1) & !found_first_bit){
            found_first_bit = true;
        }
    }
    res
}

pub fn curve_precompute_table(p1: [[Field; 4]; 2], p2: [[Field; 4]; 2]) -> [[[[Field; 4]; 2]; 4]; 4]{
    let p1_double = curve_double(p1);
    let p2_double = curve_double(p2);
    let p1_triple = curve_add(p1, p1_double);
    let p2_triple = curve_add(p2, p2_double);

    let mut res: [[[[Field; 4]; 2]; 4]; 4] = [[[[0; 4]; 2]; 4]; 4];

    res[0][1] = p2;
    res[0][2] = p2_double;
    res[0][3] = p2_triple;

    res[1][0] = p1;
    res[2][0] = p1_double;
    res[3][0] = p1_triple;

    res[2][2] = curve_add(p1_double, p2_double);
    res[1][2] = curve_add(p1, p2_double);
    res[1][1] = curve_add(p1, p2);
    res[2][1] = curve_add(p1_double, p2);

    res[3][1] = curve_add(p1_triple, p2);
    res[3][2] = curve_add(p1_triple, p2_double);
    res[3][3] = curve_add(p1_triple, p2_triple);
    res[2][3] = curve_add(p1_double, p2_triple);
    res[1][3] = curve_add(p1, p2_triple);

    res
}   

pub fn get_val_from_table(table: [[[[Field; 4]; 2]; 4]; 4], x: u32, y: u32) -> [[Field; 4]; 2]{
    table[x][y]
}

pub fn curve_two_mult(p1: [[Field; 4];2], p2: [[Field; 4];2], scalars:[[u1; 384]; 2]) -> [[Field; 4]; 2]{
    let table = curve_precompute_table(p1, p2);

    let s1_bits = scalars[0];
    let s2_bits = scalars[1];

    let mut res = [[0; 4]; 2];
    let mut found_first_bit = false;
    for i in 0..192{

        if (found_first_bit){
            res = curve_double(curve_double(res));
            if (!(s1_bits[2*i] as Field * 2 + s1_bits[2*i+1] as Field + s2_bits[2*i] as Field * 2 + s2_bits[2*i+1] as Field).eq(0)){
                res = curve_add(res, get_val_from_table(table,(s1_bits[2*i] as u32 * 2 + s1_bits[2*i+1] as u32), (s2_bits[2*i] as u32 * 2 + s2_bits[2*i+1] as u32)));
            }
        }

        if !(s1_bits[2*i] as Field * 2 + s1_bits[2*i+1] as Field + s2_bits[2*i] as Field * 2 + s2_bits[2*i+1] as Field).eq(0) & !found_first_bit {
            found_first_bit = true;
            res = get_val_from_table(table, (s1_bits[2*i] as u32 * 2 + s1_bits[2*i+1] as u32), (s2_bits[2*i] as u32 * 2 + s2_bits[2*i+1] as u32));
        }
    }

    res
}   

pub fn ecdsa_ver(sig: [[Field; 4]; 2], pk: [[Field; 4]; 2], hashed: [u8; 48]) {

    let h: BigNum<4, 384, Brainpool384r1_Fr_Params> = BigNum::from_be_bytes::<48>(hashed);

    let r: BigNum<4, 384, Brainpool384r1_Fr_Params> = BigNum{
        limbs: sig[0]
    };

    let s: BigNum<4, 384, Brainpool384r1_Fr_Params> = BigNum{
        limbs: sig[1]
    };

    let s_inv = s.__invmod();
    assert(s_inv.mul(s) == BigNum::one(), "");

    let hs = s_inv.mul(h);
    let rs = s_inv.mul(r);

    let mut scalars = [[0; 384]; 2];
    for i in 0..3{
        let tmp_bits_0 = hs.limbs[2 - i].to_be_bits::<120>();
        let tmp_bits_1 = rs.limbs[2 - i].to_be_bits::<120>();
        for j in 0..120{
            scalars[0][j + 120 * i + 24] = tmp_bits_0[j];
            scalars[1][j + 120 * i + 24] = tmp_bits_1[j];
        }
    }
    let tmp_bits_0 = hs.limbs[3].to_be_bits::<24>();
    let tmp_bits_1 = rs.limbs[3].to_be_bits::<24>();
    for j in 0..24{
        scalars[0][j] = tmp_bits_0[j];
        scalars[1][j] = tmp_bits_1[j];
    }

    let r_point = curve_two_mult(Brainpool384R1_GENERATOR, pk, scalars);

    assert(r_point[0][0] == sig[0][0], "");
    assert(r_point[0][1] == sig[0][1], "");

}   


// #[test]
// fn test_add(){
//     curve_add([[0x3c1d356c21122343280d6115c1d21, 0xb70e0cbd6bb4bf7f321390b94a],[0x4375a05a07476444d5819985007e34, 0xbd376388b5f723fb4c22dfe6cd]], [[0x474788d16dc18032d268fd1a704fa6, 0x706a46dc76dcb76798e60e6d89],[0x892849fca629487acf3709d2e4e8bb, 0x1c2b76a7bc25e7702a704fa986]]);
// }

#[test]
fn test_double(){
    curve_double(Brainpool384R1_GENERATOR);
}

#[test]
fn test_mult(){
    print(curve_mult(Brainpool384R1_GENERATOR, [1;384]));
}

// #[test]
// fn test_2_mult(){
//     print(
//         curve_two_mult(
//             [[0x3c1d356c21122343280d6115c1d21, 0xb70e0cbd6bb4bf7f321390b94a],[0x4375a05a07476444d5819985007e34, 0xbd376388b5f723fb4c22dfe6cd]], 
//             [[0xcb2bba8f6e37e45621789743cd6633, 0x25a4b8ef0ae112d28aa95742d5],[0x8713800a75730121b92a8740249441, 0x9acf510689f8654b9e1866ae24]],
//             [0x21695a86c5d1c5b572ec36da8bbe5818188492e672a64a0f09cb3f95, 0x9cdf6edcbed49fd11fdfe5b3eeea9b1b472d50625919db29c85c5751]
//     ));
// }

#[test]
fn test_ecdsa(){
    ecdsa_ver(
    [[0x7a8855eb90334c4ff61dece5b6fa5a,0x106064d099da31b6001a10717a0d39,0xce19eb437ad8a4103f78b3cb363959,0x208b6d],[0x514fd4b6050c942fa37100340ea744,0x91902ac1b543f5055b03041123bf15,0x8abb5c4e5d239ddc066ce6de430031,0x7bbc3e]],
    [[0x539421615e17b75e17cdc95c4bee88,0xa85729b74f86d247c848b7b8eddb2,0xc0e4c5d91e5b17729ba9595f9ea61c,0x1112d9],[0x854d03200e9fee2c5fa88cc604e6b8,0x5aa865926c958e2219f756adbf2496,0x3671411e713fc50322c51fbb84bccc,0x288fdd]],
    [201, 155, 250, 252, 4, 54, 113, 49, 231, 146, 193, 56, 55, 25, 35, 141, 43, 206, 141, 76, 145, 206, 183, 109, 115, 243, 168, 12, 180, 217, 151, 71, 8, 104, 174, 25, 247, 72, 232, 24, 59, 130, 255, 70, 170, 62, 221, 106]
    );
}