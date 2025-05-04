use crate::bignum::{BigNum, params::{BigNumParams, BigNumParamsGetter}};


global TWO_POWER_120: Field = 1329227995784915872903807060280344576;

global SECP224R1_GENERATOR: [[Field; 2]; 2] = [[0x3c1d356c21122343280d6115c1d21, 0xb70e0cbd6bb4bf7f321390b94a],[0x4375a05a07476444d5819985007e34, 0xbd376388b5f723fb4c22dfe6cd]];

global Secp224r1_Fq_PARAMS: BigNumParams<2, 224> = BigNumParams::new(
    true,
    [0xffffff000000000000000000000001, 0xffffffffffffffffffffffffff], 
    [0xffffffffffffffffffffffff0, 0x1000000000000000000000000000]
);

pub struct Secp224r1_Fq_Params {}

impl BigNumParamsGetter<2, 224> for Secp224r1_Fq_Params {
    fn get_params() -> BigNumParams<2, 224> {
        Secp224r1_Fq_PARAMS
    }
}

pub struct Secp224r1_Fr_Params {}

impl BigNumParamsGetter<2, 224> for Secp224r1_Fr_Params {
    fn get_params() -> BigNumParams<2, 224> {
        Secp224r1_Fr_PARAMS
    }
}

global Secp224r1_Fr_PARAMS: BigNumParams<2, 224> = BigNumParams::new(
    true,
    [0xff16a2e0b8f03e13dd29455c5c2a3d, 0xffffffffffffffffffffffffff], 
    [0xe95d1f470fc1ec22d6baa3a3d5c3d, 0x1000000000000000000000000000]
);


global a: BigNum<2, 224, Secp224r1_Fq_Params> = BigNum {
    limbs: [0xfffffefffffffffffffffffffffffe, 0xffffffffffffffffffffffffff]
};

global b: BigNum<2, 224, Secp224r1_Fq_Params> = BigNum {
    limbs: [0x44b0b7d7bfd8ba270b39432355ffb4, 0xb4050a850c04b3abf541325650]
};

pub fn curve_add(in1: [[Field; 2];2], in2: [[Field; 2];2]) -> [[Field; 2]; 2]{

    let x1: BigNum<2, 224, Secp224r1_Fq_Params> = BigNum {
        limbs: {
            in1[0]
        },
    };

    let y1: BigNum<2, 224, Secp224r1_Fq_Params> = BigNum {
        limbs: {
            in1[1]
        },
    };

    let x2: BigNum<2, 224, Secp224r1_Fq_Params> = BigNum {
        limbs: {
            in2[0]
        },
    };

    let y2: BigNum<2, 224, Secp224r1_Fq_Params> = BigNum {
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

pub fn curve_double(in1: [[Field; 2];2]) -> [[Field; 2]; 2]{
    
    let x1: BigNum<2, 224, Secp224r1_Fq_Params> = BigNum {
        limbs: {
            in1[0]
        },
    };

    let y1: BigNum<2, 224, Secp224r1_Fq_Params> = BigNum {
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

pub fn curve_mult(in1: [[Field; 2];2], scalar: Field) -> [[Field; 2]; 2]{
    let scalar_bits: [u1; 224]= scalar.to_be_bits::<224>();

    let mut res = in1;
    let mut found_first_bit= false;

    for i in 0..224{
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

pub fn curve_precompute_table(p1: [[Field; 2]; 2], p2: [[Field; 2]; 2]) -> [[[[Field; 2]; 2]; 4]; 4]{
    let p1_double = curve_double(p1);
    let p2_double = curve_double(p2);
    let p1_triple = curve_add(p1, p1_double);
    let p2_triple = curve_add(p2, p2_double);

    let mut res: [[[[Field; 2]; 2]; 4]; 4] = [[[[0; 2]; 2]; 4]; 4];

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

pub fn get_val_from_table(table: [[[[Field; 2]; 2]; 4]; 4], x: u32, y: u32) -> [[Field; 2]; 2]{
    table[x][y]
}

pub fn curve_two_mult(p1: [[Field; 2];2], p2: [[Field; 2];2], scalars:[Field; 2]) -> [[Field; 2]; 2]{
    let table = curve_precompute_table(p1, p2);

    let s1_bits = scalars[0].to_be_bits::<224>();
    let s2_bits = scalars[1].to_be_bits::<224>();

    let mut res = [[0; 2];2];
    let mut found_first_bit = false;
    for i in 0..112{

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

pub fn ecdsa_ver(sig: [[Field; 2]; 2], pk: [[Field; 2]; 2], hashed: [u8; 28]) {

    let h: BigNum<2, 224, Secp224r1_Fr_Params> = BigNum::from_be_bytes::<28>(hashed);

    let r: BigNum<2, 224, Secp224r1_Fr_Params> = BigNum{
        limbs: sig[0]
    };

    let s: BigNum<2, 224, Secp224r1_Fr_Params> = BigNum{
        limbs: sig[1]
    };

    let s_inv = s.__invmod();
    assert(s_inv.mul(s) == BigNum::one(), "");

    let hs = s_inv.mul(h);
    let rs = s_inv.mul(r);

    let mut scalars = [0; 2];
    scalars[0] = hs.limbs[0] + hs.limbs[1] * TWO_POWER_120;
    scalars[1] = rs.limbs[0] + rs.limbs[1] * TWO_POWER_120;

    let r_point = curve_two_mult(SECP224R1_GENERATOR, pk, scalars);

    assert(r_point[0][0] == sig[0][0], "");
    assert(r_point[0][1] == sig[0][1], "");

}   


#[test]
fn test_add(){
    curve_add([[0x3c1d356c21122343280d6115c1d21, 0xb70e0cbd6bb4bf7f321390b94a],[0x4375a05a07476444d5819985007e34, 0xbd376388b5f723fb4c22dfe6cd]], [[0x474788d16dc18032d268fd1a704fa6, 0x706a46dc76dcb76798e60e6d89],[0x892849fca629487acf3709d2e4e8bb, 0x1c2b76a7bc25e7702a704fa986]]);
}

#[test]
fn test_double(){
    curve_double([[0x3c1d356c21122343280d6115c1d21, 0xb70e0cbd6bb4bf7f321390b94a],[0x4375a05a07476444d5819985007e34, 0xbd376388b5f723fb4c22dfe6cd]]);
}

#[test]
fn test_mult(){
    print(curve_mult([[0x3c1d356c21122343280d6115c1d21, 0xb70e0cbd6bb4bf7f321390b94a],[0x4375a05a07476444d5819985007e34, 0xbd376388b5f723fb4c22dfe6cd]], 0x21695a86c5d1c5b572ec36da8bbe5818188492e672a64a0f09cb3f95));
}

#[test]
fn test_2_mult(){
    print(
        curve_two_mult(
            [[0x3c1d356c21122343280d6115c1d21, 0xb70e0cbd6bb4bf7f321390b94a],[0x4375a05a07476444d5819985007e34, 0xbd376388b5f723fb4c22dfe6cd]], 
            [[0xcb2bba8f6e37e45621789743cd6633, 0x25a4b8ef0ae112d28aa95742d5],[0x8713800a75730121b92a8740249441, 0x9acf510689f8654b9e1866ae24]],
            [0x21695a86c5d1c5b572ec36da8bbe5818188492e672a64a0f09cb3f95, 0x9cdf6edcbed49fd11fdfe5b3eeea9b1b472d50625919db29c85c5751]
    ));
}

#[test]
fn test_ecdsa(){
    ecdsa_ver(
    [
            [0xa02f538fd0064120faa824002101db, 0x4c4d8999f5936d9123b194444b],
            [0x5822aaab85c653b663f2eea4c2d6e5, 0x6c5214f7ea4b12df4fdfdea37]
        ],
    [
            [722371281012593104244619201166496731, 8945567368764448446025875086533],
            [349435418845284657361889125617340902, 7867863669378148314177957488491]
        ],
[177, 28, 121, 26, 76, 57, 86, 171, 94, 117, 165, 108, 210, 252, 245, 238, 118, 238, 75, 9, 79, 14, 196, 133, 173, 87, 243, 102]
    );
}