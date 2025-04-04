use std::ops::Not;

pub mod binary;

fn bin_add<let N: u32>(a: [u64; N], b: [u64; N]) -> [u64; N]{
    let mut out: [u64; N] = [0; N];
    for i in 0..N{
        out[i] = a[i] ^ b[i];
    }
    out
}

fn reduce_poly<let N: u32, let CURVE_BITS: u32>(a: [u64; N]) -> [u64; N]{
    let mut out: [u64; N] = a;
    if (CURVE_BITS == 163){
        // poly = x**163 + x**7 + x**6 + x**3 + 1
        let bits: [u1; 38] = (a[N - 1] as Field).to_le_bits();
        let bit = bits[37];

        let bit_u64 = bit as u64;
        out[0] = (out[0] ^ 201) * bit_u64 + out[0] * (1 - bit_u64);
        out[N-1] = (out[N-1] ^ 16) * bit_u64 + out[N-1] * (1 - bit_u64);
    }
    if (CURVE_BITS == 571){
        // poly = x**571 + x**10 + x**5 + x**2 + 1
        let bits: [u1; 5] = (a[N - 1] as Field).to_le_bits();
        let bit = bits[4];

        let bit_u64 = bit as u64;
        out[0] = (out[0] ^ 1061) * bit_u64 + out[0] * (1 - bit_u64);
        out[N-1] = (out[N-1] ^ 137438953472) * bit_u64 + out[N-1] * (1 - bit_u64);
    }
    out
}

fn bit_shift<let N: u32>(a: [u64; N]) -> [u64; N]{
    let mut out: [u64; N] = [0; N];
    let mut carry = 0;
    for i in 0..(N-1){
        out[i] = a[i] * 2 + carry;
        carry = out[i] / 9223372036854775808; // 2**63
        out[i] = out[i] % 9223372036854775808;
    }
    out[N - 1] = a[N - 1] * 2 + carry;
    out
}

fn bin_mult<let N: u32, let CURVE_BITS: u32>(a: [u64; N], b: [u64; N]) -> [u64; N]{
    let mut a_bits: [u1; CURVE_BITS] = [0; CURVE_BITS];

    for i in 0..N{
        if i != (N - 1){
            let bits: [u1; 64] = (a[i] as Field).to_le_bits();
            for j in 0..64{
                a_bits[i * 64 + j] = bits[j];
            }
        } else {
             let bits: [u1; CURVE_BITS % 64] = (a[i] as Field).to_le_bits();
            for j in 0..(CURVE_BITS % 64){
                a_bits[i * 64 + j] = bits[j];
            }
        }
    }

    let mut res: [u64; N] = [0; N];
    let mut b_clone: [u64; N] = b;
    for i in 0..CURVE_BITS{
        let mut adder: [u64; N] = [0; N];
        for j in 0..N{
            adder[j] = (a_bits[i] as u64) * b_clone[j];
        }
        res = bin_add::<N>(res, adder);
        b_clone = bit_shift::<N>(b_clone);
        res = reduce_poly::<N, CURVE_BITS>(res);
    }
    res
}

// fn main(a: [u64; 3]) -> pub [u64; 3]{
//     // bin_mult::<3, 571>(a, a)
//     reduce_poly::<3, 163>(a)
// } 

fn main(a: [u8; 2]) -> pub [u8; 32]{
    std::sha256::digest(a)
}

unconstrained fn get_bits<let N: u32>(a: Field) -> [Field; N] {
    let bits = a.to_le_bits::<N>();
    let mut res= [0; N];
    for i in 0..N{
        res[i] = bits[i] as Field;
    }
    res
}

fn num_to_bits<let N: u32>(a: Field) -> [Field; N]{
    
    let mut result = [0; N];

    let bits = get_bits::<N>(a);
    let mut current = 1;
    let mut result = 0;
    for i in 0..N{
        assert(bits[i] * (1 - bits[i]) == 0, "HUI");
        result += bits[i] * current;
        current *= 2;
    }
    assert(result == a, "hui");

    bits
}

fn bits_to_num<let N: u32>(a: [Field; N])->Field{
    let mut current = 1;
    let mut result = 0;

    for i in 0..N{
        result += a[i] * current;
        current *= 2;
    }
    result
}

#[test]
// fn test_main(){
//     print(main([3, 0, 0]))
// } 