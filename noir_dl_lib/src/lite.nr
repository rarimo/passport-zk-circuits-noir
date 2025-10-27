use crate::not_passports_zk_circuits::{extract_dg1_commitment, extract_pk_identity_hash, passport_hash};

pub fn register_identity_light<
    let DG1_LEN: u32,
    let DG_HASH_ALGO: u32,
>(
    dg1: [u8; DG1_LEN],
    sk_identity: Field,

) -> (Field, Field, Field){

    
    let sk_hash = extract_pk_identity_hash(sk_identity);
    let dg1_commitment = extract_dg1_commitment::<DG1_LEN>(dg1, sk_identity);
    let dg1_hash_bytes: [u8; DG_HASH_ALGO] = passport_hash::<DG_HASH_ALGO, DG1_LEN>(dg1);
    let mut dg1_hash: Field = 0;

    let mut hash_diff = 0;
    if (DG_HASH_ALGO < 31){
        hash_diff = 31 - DG_HASH_ALGO;
    }

    let mut current = 1;
    for i in 0..(31 - hash_diff){
        dg1_hash += current * dg1_hash_bytes[DG_HASH_ALGO - 1 - i] as Field;
        current *= 256;
    }

    (dg1_commitment, dg1_hash, sk_hash)
}

