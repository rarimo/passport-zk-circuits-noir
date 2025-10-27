use ripemd160::ripemd160;
use super::{big_curve::curves::secp256k1::Secp256k1_Params, big_curve::curves::secp256k1::Secp256k1Fr, big_curve::scalar_field::ScalarField, big_curve::curves::secp256k1::Secp256k1Fq, big_curve::curves::secp256k1::Secp256k1, bignum::bignum::BigNum};

pub fn priv_to_pub(priv: [u8; 32]) -> [u8; 65]{
    let gen = Secp256k1::one();
    let scalar_bignum: Secp256k1Fq = BigNum::from_be_bytes(priv);
    let scalar: ScalarField<65> = ScalarField::from_bignum(scalar_bignum);
    let pubkey = gen.mul(scalar);
    let x_limbs = pubkey.x.limbs;
    let y_limbs = pubkey.y.limbs;
    let mut pubkey_bytes = [4; 65];
    
    let mut tmp_bits_2 = x_limbs[2].to_be_bytes::<2>();

    for i in 0..2{
        pubkey_bytes[i+1] = tmp_bits_2[i];
    }

    let mut tmp_bits_15 = x_limbs[1].to_be_bytes::<15>();

    for i in 0..15{
        pubkey_bytes[i+3] = tmp_bits_15[i];
    }

    tmp_bits_15 = x_limbs[0].to_be_bytes::<15>();

    for i in 0..15{
        pubkey_bytes[i+18] = tmp_bits_15[i];
    }

    tmp_bits_2 = y_limbs[2].to_be_bytes::<2>();

    for i in 0..2{
        pubkey_bytes[i+33] = tmp_bits_2[i];
    }

    let mut tmp_bits_15 = y_limbs[1].to_be_bytes::<15>();

    for i in 0..15{
        pubkey_bytes[i+35] = tmp_bits_15[i];
    }

    tmp_bits_15 = y_limbs[0].to_be_bytes::<15>();

    for i in 0..15{
        pubkey_bytes[i+50] = tmp_bits_15[i];
    }

    pubkey_bytes
}

fn pub_to_addr(pubkey: [u8; 65])->[u8; 20]{
    let hash = std::sha256::digest(pubkey);
    ripemd160(hash)
}

#[test]
fn t(){
    let mut tmp = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1];
    let pubkey = priv_to_pub(tmp);
    let addr = pub_to_addr(pubkey);

    assert(addr == [145, 178, 75, 249, 245, 40, 133, 50, 150, 10, 198, 135, 171, 176, 53, 18, 123, 29, 40, 165]);
}