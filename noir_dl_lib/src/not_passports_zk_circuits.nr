use std::{field, hash::poseidon::PoseidonHasher};
use super::{sigver, sigver::curve_224::ecdsa_ver, sigver::ecdsa::verify_secp521r1_ecdsa, sigver::ecdsa::verify_brainpoolp512r1_ecdsa, sigver::ecdsa::verify_brainpoolp384r1_ecdsa, sigver::ecdsa::verify_secp256r1_ecdsa, big_curve::curves::secp256r1::Secp256r1Fr, sigver::ecdsa::verify_brainpoolp256r1_ecdsa, big_curve::curves::secp256r1::Secp256r1Fq};
use crate::bignum::BigNum;
use crate::sigver::brainpoolP256r1::params::{BrainpoolP256r1Fq, BrainpoolP256r1Fr};
use crate::sigver::brainpoolP384r1::params::{BrainpoolP384r1Fq, BrainpoolP384r1Fr};
use crate::sigver::brainpoolP512r1::params::{BrainpoolP512r1Fq, BrainpoolP512r1Fr};
use crate::sigver::secp521r1::params::{Secp521r1Fq, Secp521r1Fr};

pub fn register_identity<
    let DG1_LEN: u32,
    let DG15_LEN: u32,
    let EC_LEN: u32,
    let SA_LEN: u32,
    let N: u32,
    let EC_FIELD_SIZE: u32,
    let DG_HASH_ALGO: u32,
    let HASH_ALGO: u32,
    let SIG_TYPE: u32,
    let DG1_SHIFT: u32,
    let DG15_SHIFT: u32,
    let EC_SHIFT: u32,
    let AA_SIG_TYPE: u32,
    let AA_SHIFT: u32>(
    dg1: [u8; DG1_LEN],
    dg15: [u8; DG15_LEN],
    ec: [u8; EC_LEN],
    sa: [u8; SA_LEN],
    pk: [Field; N], 
    reduction_pk: [Field; N],
    sig: [Field; N],
    sk_identity: Field,
    icao_root: Field,
    inclusion_brances: [Field; 80]
    ) -> (Field, Field, Field, Field){
    
    // 1. Verify flow

    let _ = passport_verification_flow::<
        DG1_LEN, 
        DG15_LEN, 
        EC_LEN, 
        SA_LEN, 
        DG_HASH_ALGO,
        HASH_ALGO,
        DG1_SHIFT,
        DG15_SHIFT,
        EC_SHIFT,
        >(dg1, dg15, ec, sa);

    // 2. Verify signature

    let mut sa_hash: [u8; HASH_ALGO] = passport_hash::<HASH_ALGO, SA_LEN>(sa);
    if (SIG_TYPE == 24){
        let tmp_hash: [u8; 28] = passport_hash::<28, SA_LEN>(sa);
        for i in 0..28{
            sa_hash[i] = tmp_hash[i];
        }
    }

    let _ = verify_signature::<
            N, SIG_TYPE, HASH_ALGO
        >(
            pk, reduction_pk, sig, 
            sa_hash
        );

    // 3. Verfiy merkle tree inclusion proof
    let leaf = extract_pk_hash::<N, EC_FIELD_SIZE, SIG_TYPE>(pk);
    let key  = leaf;
    let is_verfied = super::smt::smt_verifier::<80>(icao_root, leaf, key, inclusion_brances);
    assert(is_verfied == 1, "Merkle tree verification failure");

    // 4. Get dg15 pubkey hash
    let dg15_pk_hash = extract_dg15_pk_hash::<DG15_LEN, AA_SHIFT, AA_SIG_TYPE>(dg15);
    // let dg15_pk_hash = 0;

    // 5. Get dg1Commitment
    let dg1_commitment = extract_dg1_commitment::<DG1_LEN>(dg1, sk_identity);

    // 6. sk_iden_hash
    let sk_hash = extract_pk_identity_hash(sk_identity);

    // 7. Get passport hash
    let passport_hash = extract_passport_hash::<HASH_ALGO>(sa_hash);

    (dg15_pk_hash, passport_hash, dg1_commitment, sk_hash)
        
}

fn passport_verification_flow<
    let DG1_LEN: u32,
    let DG15_LEN: u32,
    let EC_LEN: u32,
    let SA_LEN: u32,
    let DG_HASH_ALGO: u32,
    let HASH_ALGO: u32,
    let DG1_SHIFT: u32,
    let DG15_SHIFT: u32,
    let EC_SHIFT: u32>(
        dg1: [u8; DG1_LEN],
        dg15: [u8; DG15_LEN],
        ec: [u8; EC_LEN],
        sa: [u8; SA_LEN],
    ){
    
    let dg1_hash: [u8; DG_HASH_ALGO] = passport_hash::<DG_HASH_ALGO, DG1_LEN>(dg1);

    
    let mut dg15_hash: [u8; DG_HASH_ALGO] = [0; DG_HASH_ALGO];
    if (DG15_LEN != 0){
        dg15_hash = passport_hash::<DG_HASH_ALGO, DG15_LEN>(dg15);
    }
    let ec_hash: [u8; HASH_ALGO] = passport_hash::<HASH_ALGO, EC_LEN>(ec);
    
    for i in 0..DG_HASH_ALGO{
        assert(dg1_hash[i] == ec[i + DG1_SHIFT], "dg1 mismatch");
        if (DG15_LEN != 0){
            assert(dg15_hash[i] == ec[i + DG15_SHIFT], "dg15 mismatch");
        }
    }
    for i in 0..HASH_ALGO{
        assert(ec_hash[i] == sa[i + EC_SHIFT], "ec mismatch");
    }
}

fn verify_signature<
    let N: u32,
    let SIG_TYPE: u32,
    let HASH_ALGO: u32>(
    pk: [Field; N],
    reduction_pk: [Field; N],
    sig: [Field; N],
    hashed: [u8; HASH_ALGO]
    ){
    
    if (SIG_TYPE == 1){

        let mut pk_fixed: [Field; 18] = [0; 18];
        let mut red_fixed: [Field; 18] = [0; 18];
        let mut sig_fixed: [Field; 18] = [0; 18];

        for i in 0..18{
            pk_fixed[i] = pk[i];
            red_fixed[i] = reduction_pk[i];
            sig_fixed[i] = sig[i];
        }

        let _ = super::rsa::verify_rsa::<2048, 18, HASH_ALGO, 65537>(
            pk_fixed, 
            red_fixed, 
            sig_fixed, 
            hashed
        );
    }
    if (SIG_TYPE == 2){
        let mut pk_fixed: [Field; 35] = [0; 35];
        let mut red_fixed: [Field; 35] = [0; 35];
        let mut sig_fixed: [Field; 35] = [0; 35];

        for i in 0..35{
            pk_fixed[i] = pk[i];
            red_fixed[i] = reduction_pk[i];
            sig_fixed[i] = sig[i];
        }

        let _ = super::rsa::verify_rsa::<4096, 35, HASH_ALGO, 65537>(
            pk_fixed, 
            red_fixed, 
            sig_fixed, 
            hashed
        );

    }
    if (SIG_TYPE == 3){

        let mut pk_fixed: [Field; 18] = [0; 18];
        let mut red_fixed: [Field; 18] = [0; 18];
        let mut sig_fixed: [Field; 18] = [0; 18];

        for i in 0..18{
            pk_fixed[i] = pk[i];
            red_fixed[i] = reduction_pk[i];
            sig_fixed[i] = sig[i];
        }


        let _ = super::rsa::verify_rsa::<2048, 18, HASH_ALGO, 65537>(
            pk_fixed, 
            red_fixed, 
            sig_fixed, 
            hashed
        );
    }
    if (SIG_TYPE == 4){

        let mut pk_fixed: [Field; 18] = [0; 18];
        let mut red_fixed: [Field; 18] = [0; 18];
        let mut sig_fixed: [Field; 18] = [0; 18];

        for i in 0..18{
            pk_fixed[i] = pk[i];
            red_fixed[i] = reduction_pk[i];
            sig_fixed[i] = sig[i];
        }


        let _ = super::rsa::verify_rsa::<2048, 18, HASH_ALGO, 37187>(
            pk_fixed, 
            red_fixed, 
            sig_fixed, 
            hashed
        );
    }
    if (SIG_TYPE == 5){

        let mut pk_fixed: [Field; 18] = [0; 18];
        let mut red_fixed: [Field; 18] = [0; 18];
        let mut sig_fixed: [Field; 18] = [0; 18];

        for i in 0..18{
            pk_fixed[i] = pk[i];
            red_fixed[i] = reduction_pk[i];
            sig_fixed[i] = sig[i];
        }


        let _ = super::rsa::verify_rsa::<2048, 18, HASH_ALGO, 65537>(
            pk_fixed, 
            red_fixed, 
            sig_fixed, 
            hashed
        );
    }
    if (SIG_TYPE == 6){

        let mut pk_fixed: [Field; 26] = [0; 26];
        let mut red_fixed: [Field; 26] = [0; 26];
        let mut sig_fixed: [Field; 26] = [0; 26];

        for i in 0..26{
            pk_fixed[i] = pk[i];
            red_fixed[i] = reduction_pk[i];
            sig_fixed[i] = sig[i];
        }


        let _ = super::rsa::verify_rsa::<3072, 26, HASH_ALGO, 58333>(
            pk_fixed, 
            red_fixed, 
            sig_fixed, 
            hashed
        );
    }
    if (SIG_TYPE == 7){

        let mut pk_fixed: [Field; 26] = [0; 26];
        let mut red_fixed: [Field; 26] = [0; 26];
        let mut sig_fixed: [Field; 26] = [0; 26];

        for i in 0..26{
            pk_fixed[i] = pk[i];
            red_fixed[i] = reduction_pk[i];
            sig_fixed[i] = sig[i];
        }


        let _ = super::rsa::verify_rsa::<3072, 26, HASH_ALGO, 45347>(
            pk_fixed, 
            red_fixed, 
            sig_fixed, 
            hashed
        );
    }
    if (SIG_TYPE == 8){

        let mut pk_fixed: [Field; 26] = [0; 26];
        let mut red_fixed: [Field; 26] = [0; 26];
        let mut sig_fixed: [Field; 26] = [0; 26];

        for i in 0..26{
            pk_fixed[i] = pk[i];
            red_fixed[i] = reduction_pk[i];
            sig_fixed[i] = sig[i];
        }


        let _ = super::rsa::verify_rsa::<3072, 26, HASH_ALGO, 46271>(
            pk_fixed, 
            red_fixed, 
            sig_fixed, 
            hashed
        );
    }

    if (SIG_TYPE == 10){
        let mut pk_fixed: [Field; 18] = [0; 18];
        let mut red_fixed: [Field; 18] = [0; 18];
        let mut sig_fixed: [Field; 18] = [0; 18];

        for i in 0..18{
            pk_fixed[i] = pk[i];
            red_fixed[i] = reduction_pk[i];
            sig_fixed[i] = sig[i];
        }

        let _ = super::rsa_pss::verify_rsa_pss::<2048, 18, HASH_ALGO, 32, 3>(
            pk_fixed, 
            red_fixed, 
            sig_fixed, 
            hashed
        );
    }
    if (SIG_TYPE == 11){

        let mut pk_fixed: [Field; 18] = [0; 18];
        let mut red_fixed: [Field; 18] = [0; 18];
        let mut sig_fixed: [Field; 18] = [0; 18];

        for i in 0..18{
            pk_fixed[i] = pk[i];
            red_fixed[i] = reduction_pk[i];
            sig_fixed[i] = sig[i];
        }
        
        let _ = super::rsa_pss::verify_rsa_pss::<2048, 18, HASH_ALGO, 32, 65537>(
            pk_fixed, 
            red_fixed, 
            sig_fixed, 
            hashed
        );
    }
    if (SIG_TYPE == 12){

        let mut pk_fixed: [Field; 18] = [0; 18];
        let mut red_fixed: [Field; 18] = [0; 18];
        let mut sig_fixed: [Field; 18] = [0; 18];

        for i in 0..18{
            pk_fixed[i] = pk[i];
            red_fixed[i] = reduction_pk[i];
            sig_fixed[i] = sig[i];
        }

        let _ = super::rsa_pss::verify_rsa_pss::<2048, 18, HASH_ALGO, 64, 65537>(
            pk_fixed, 
            red_fixed, 
            sig_fixed, 
            hashed
        );
    }
    if (SIG_TYPE == 13){
           
        let mut pk_fixed: [Field; 18] = [0; 18];
        let mut red_fixed: [Field; 18] = [0; 18];
        let mut sig_fixed: [Field; 18] = [0; 18];

        for i in 0..18{
            pk_fixed[i] = pk[i];
            red_fixed[i] = reduction_pk[i];
            sig_fixed[i] = sig[i];
        }

        let _ = super::rsa_pss::verify_rsa_pss::<2048, 18, HASH_ALGO, 48, 65537>(
            pk_fixed, 
            red_fixed, 
            sig_fixed, 
            hashed
        );
    }
    if (SIG_TYPE == 14){
        let mut pk_fixed: [Field; 26] = [0; 26];
        let mut red_fixed: [Field; 26] = [0; 26];
        let mut sig_fixed: [Field; 26] = [0; 26];

        for i in 0..26{
            pk_fixed[i] = pk[i];
            red_fixed[i] = reduction_pk[i];
            sig_fixed[i] = sig[i];
        }
        
        let _ = super::rsa_pss::verify_rsa_pss::<3072, 26, HASH_ALGO, 32, 65537>(
            pk_fixed, 
            red_fixed, 
            sig_fixed, 
            hashed
        );
    }
    if (SIG_TYPE == 15){

        let mut pk_fixed: [Field; 18] = [0; 18];
        let mut red_fixed: [Field; 18] = [0; 18];
        let mut sig_fixed: [Field; 18] = [0; 18];

        for i in 0..18{
            pk_fixed[i] = pk[i];
            red_fixed[i] = reduction_pk[i];
            sig_fixed[i] = sig[i];
        }


        let _ = super::rsa_pss::verify_rsa_pss::<2048, 18, HASH_ALGO, 64, 65537>(
            pk_fixed, 
            red_fixed, 
            sig_fixed, 
            hashed
        );
    }
    if (SIG_TYPE == 21){
        let mut limbs_x: [Field; 3] = [0; 3];
        let mut limbs_y: [Field; 3] = [0; 3];
        let mut limbs_r: [Field; 3] = [0; 3];
        let mut limbs_s: [Field; 3] = [0; 3];

        for i in 0..3{
            limbs_x[i] = pk[i];
            limbs_y[i] = pk[i + 3];
            limbs_r[i] = sig[i];
            limbs_s[i] = sig[i + 3];   
        }

        let r: BrainpoolP256r1Fr = BigNum {
            limbs: limbs_r,
        };

        let s: BrainpoolP256r1Fr = BigNum {
            limbs: limbs_s
        };

        let public_key_x: BrainpoolP256r1Fq = BigNum {
            limbs: limbs_x
        };

        let public_key_y: BrainpoolP256r1Fq = BigNum {
            limbs: limbs_y
        };

        assert(verify_brainpoolp256r1_ecdsa(public_key_x, public_key_y, hashed, (r, s)));
    }
    if (SIG_TYPE == 20){
        let mut limbs_x: [Field; 3] = [0; 3];
        let mut limbs_y: [Field; 3] = [0; 3];
        let mut limbs_r: [Field; 3] = [0; 3];
        let mut limbs_s: [Field; 3] = [0; 3];

        for i in 0..3{
            limbs_x[i] = pk[i];
            limbs_y[i] = pk[i + 3];
            limbs_r[i] = sig[i];
            limbs_s[i] = sig[i + 3];   
        }

        let r: Secp256r1Fr = BigNum {
            limbs: limbs_r,
        };

        let s: Secp256r1Fr = BigNum {
            limbs: limbs_s
        };

        let public_key_x: Secp256r1Fq = BigNum {
            limbs: limbs_x
        };

        let public_key_y: Secp256r1Fq = BigNum {
            limbs: limbs_y
        };

        assert(verify_secp256r1_ecdsa(public_key_x, public_key_y, hashed, (r, s)));
    }

    if (SIG_TYPE == 23){
        let mut limbs_x: [Field; 2] = [0; 2];
        let mut limbs_y: [Field; 2] = [0; 2];
        let mut limbs_r: [Field; 2] = [0; 2];
        let mut limbs_s: [Field; 2] = [0; 2];

        for i in 0..2{
            limbs_x[i] = pk[i];
            limbs_y[i] = pk[i + 2];
            limbs_r[i] = sig[i];
            limbs_s[i] = sig[i + 2];   
        }

        let mut ext_hashed: [u8; 20] = [0;20];

        for i in 0..20{
            ext_hashed[i] = hashed[i];
        }

        sigver::curve_192::ecdsa_ver([limbs_r, limbs_s], [limbs_x, limbs_y], ext_hashed);
    }

    if (SIG_TYPE == 24){
        let mut limbs_x: [Field; 2] = [0; 2];
        let mut limbs_y: [Field; 2] = [0; 2];
        let mut limbs_r: [Field; 2] = [0; 2];
        let mut limbs_s: [Field; 2] = [0; 2];

        for i in 0..2{
            limbs_x[i] = pk[i];
            limbs_y[i] = pk[i + 2];
            limbs_r[i] = sig[i];
            limbs_s[i] = sig[i + 2];   
        }

        let mut ext_hashed: [u8; 28] = [0;28];

        for i in 0..28{
            ext_hashed[i] = hashed[i];
        }
        println([limbs_r, limbs_s]);
        println([limbs_x, limbs_y]);
        println(hashed);

        ecdsa_ver([limbs_r, limbs_s], [limbs_x, limbs_y], ext_hashed);
    }

    if (SIG_TYPE == 25){
        let mut limbs_x: [Field; 4] = [0; 4];
        let mut limbs_y: [Field; 4] = [0; 4];
        let mut limbs_r: [Field; 4] = [0; 4];
        let mut limbs_s: [Field; 4] = [0; 4];

        for i in 0..4{
            limbs_x[i] = pk[i];
            limbs_y[i] = pk[i + 4];
            limbs_r[i] = sig[i];
            limbs_s[i] = sig[i + 4];   
        }

        let r: BrainpoolP384r1Fr = BigNum {
            limbs: limbs_r,
        };

        let s: BrainpoolP384r1Fr = BigNum {
            limbs: limbs_s
        };

        let public_key_x: BrainpoolP384r1Fq = BigNum {
            limbs: limbs_x
        };

        let public_key_y: BrainpoolP384r1Fq = BigNum {
            limbs: limbs_y
        };
        
        assert(verify_brainpoolp384r1_ecdsa(public_key_x, public_key_y, hashed, (r, s)));
    }

    if (SIG_TYPE == 26){
        let mut limbs_x: [Field; 5] = [0; 5];
        let mut limbs_y: [Field; 5] = [0; 5];
        let mut limbs_r: [Field; 5] = [0; 5];
        let mut limbs_s: [Field; 5] = [0; 5];

        for i in 0..5{
            limbs_x[i] = pk[i];
            limbs_y[i] = pk[i + 5];
            limbs_r[i] = sig[i];
            limbs_s[i] = sig[i + 5];   
        }

        let r: BrainpoolP512r1Fr = BigNum {
            limbs: limbs_r,
        };

        let s: BrainpoolP512r1Fr = BigNum {
            limbs: limbs_s
        };

        let public_key_x: BrainpoolP512r1Fq = BigNum {
            limbs: limbs_x
        };

        let public_key_y: BrainpoolP512r1Fq = BigNum {
            limbs: limbs_y
        };
        
        assert(verify_brainpoolp512r1_ecdsa(public_key_x, public_key_y, hashed, (r, s)));
    }

    if (SIG_TYPE == 27){
        let mut limbs_x: [Field; 5] = [0; 5];
        let mut limbs_y: [Field; 5] = [0; 5];
        let mut limbs_r: [Field; 5] = [0; 5];
        let mut limbs_s: [Field; 5] = [0; 5];

        for i in 0..5{
            limbs_x[i] = pk[i];
            limbs_y[i] = pk[i + 5];
            limbs_r[i] = sig[i];
            limbs_s[i] = sig[i + 5];   
        }

        let r: Secp521r1Fr = BigNum {
            limbs: limbs_r,
        };

        let s: Secp521r1Fr = BigNum {
            limbs: limbs_s
        };

        let public_key_x: Secp521r1Fq = BigNum {
            limbs: limbs_x
        };

        let public_key_y: Secp521r1Fq = BigNum {
            limbs: limbs_y
        };
        
        assert(verify_secp521r1_ecdsa(public_key_x, public_key_y, hashed, (r, s)));
    }
}

fn extract_dg15_pk_hash<
    let DG15_LEN: u32,
    let AA_SHIFT: u32,
    let AA_SIG_TYPE: u32>(
    dg15: [u8; DG15_LEN]
    ) -> Field{
    let mut dg15_pk_hash: Field = 0;

    if (AA_SIG_TYPE != 0){
        if (AA_SIG_TYPE < 20) { // rsa keys stored
            let mut dg15_chunks: [Field; 5] = [0; 5];
            let mut poseidon_hasher: PoseidonHasher = PoseidonHasher::default();
            
            for i in 0..5{
                if (i !=4){
                    let mut current = 1;
                    for j in 0..25{ // 200 bit
                        dg15_chunks[i] += (dg15[AA_SHIFT + (24 - j) + i * 25]) as Field * current;
                        current *= 256;
                    }
                    poseidon_hasher.write(dg15_chunks[i]);

                } else {
                    let mut current = 1;
                    for j in 0..28{ // 224 bit
                        dg15_chunks[i] += (dg15[AA_SHIFT + (27 - j) + i * 25]) as Field * current;
                        current *= 256;
                    }
                    poseidon_hasher.write(dg15_chunks[i]);

                }

                dg15_pk_hash = poseidon_hasher.finish();
                
            }

        } else { // ecdsa key stored
            let mut HASH_SIZE = 31;
            let mut EC_FIELD_SIZE = 32;
            if (AA_SIG_TYPE == 22){
                EC_FIELD_SIZE = 40;
            }
            if (AA_SIG_TYPE == 23){
                EC_FIELD_SIZE = 24;
                HASH_SIZE = 24;
            }

            let X_Y_SHIFT = EC_FIELD_SIZE - HASH_SIZE;
            let mut x = 0;
            let mut y = 0;


            let mut current = 1;
            for j in 0..HASH_SIZE{ 
                x += (dg15[AA_SHIFT + (HASH_SIZE - 1 - j) + X_Y_SHIFT]) as Field * current;
                y += (dg15[AA_SHIFT + (HASH_SIZE - 1 - j) + X_Y_SHIFT + EC_FIELD_SIZE]) as Field * current;
                current *= 256;
            }

            let mut poseidon_hasher: PoseidonHasher = PoseidonHasher::default();
            poseidon_hasher.write(x);
            poseidon_hasher.write(y);
            dg15_pk_hash = poseidon_hasher.finish();
        }
    }

    dg15_pk_hash
}

pub fn extract_dg1_commitment<
    let DG1_LEN: u32>(
    dg1: [u8; DG1_LEN], 
    sk_identity: Field) -> Field{
    let mut poseidon_hasher = PoseidonHasher::default();

    let mut dg1_bits: [u1; DG1_LEN * 8] = [0; DG1_LEN * 8];

    for i in 0..DG1_LEN{
        let tmp_bits = u8_to_8_u1(dg1[i]);
        for j in 0..8{
            dg1_bits[i * 8 + j] = tmp_bits[j];
        }
    }

    for i in 0..4{
        let mut chunk = 0;
        let mut current = 1;
        for j in 0..(DG1_LEN * 2){
            chunk += (dg1_bits[i * 2 * DG1_LEN + j ] as Field) * current;
            current = current * 2;
        }
        poseidon_hasher.write(chunk);
    }

    let mut poseidon_hasher_2 = PoseidonHasher::default();
    poseidon_hasher_2.write(sk_identity);
    poseidon_hasher.write(poseidon_hasher_2.finish());

    poseidon_hasher.finish()
}

pub fn extract_pk_identity_hash<>(
    sk_identity: Field
    ) -> Field{
    let mut hasher = PoseidonHasher::default();
    let point = super::jubjub::priv_to_pub(sk_identity);
    hasher.write(point.0);
    hasher.write(point.1);
    
    hasher.finish()

}

fn extract_passport_hash<
    let HASH_TYPE:u32>(
    sa_hash: [u8; HASH_TYPE]
    )->Field{

    let mut poseidon_hasher = PoseidonHasher::default();
    let mut sa_hash_bits: [u1; 252] = [0; 252];

    if (HASH_TYPE >= 32){
        for i in 0..32{
            let tmp_bits = u8_to_8_u1(sa_hash[i]);
            if (i != 31){
                for j in 0..8{
                    sa_hash_bits[i * 8 + j] = tmp_bits[j];
                }
            } else {
                for j in 0..4{ // 248 - 251 bits
                    sa_hash_bits[i * 8 + j] = tmp_bits[j];
                }
            }
        } 
    } else {
        for i in 0..HASH_TYPE{
            let tmp_bits = u8_to_8_u1(sa_hash[i]);
            
            for j in 0..8{
                sa_hash_bits[i * 8 + j] = tmp_bits[j];
            }
        } 
    }
    let mut current = 1;
    let mut preimage = 0;
    for i in 0..252{
        preimage += (sa_hash_bits[i] as Field) * current;
        current *= 2;
    }

    poseidon_hasher.write(preimage);
    poseidon_hasher.finish()
}

fn extract_pk_hash<
    let N: u32,
    let EC_FIELD_SIZE: u32,
    let SIG_TYPE: u32>(
        pubkey: [Field; N] 
    ) -> Field{
    let mut out = 0;

    if (SIG_TYPE < 20){
        let mut pk_bits: [u1; 960] = [0; 960];
        for i in 0..8{
            let bits: [u1; 120] = pubkey[i].to_le_bits();
            for j in 0..120{
                pk_bits[i * 120 + j] = bits[j];
            }
        }

        let mut chunks: [Field; 15] = [0; 15];
        for i in 0..15{
            let mut current = 1;
            for j in 0..64{
                chunks[i] += (pk_bits[i * 64 + j] as Field) * current;
                current *= 2;
            }
        }
        let mut hasher = PoseidonHasher::default();
        for i in 0..5{
            hasher.write(chunks[i * 3] * 340282366920938463463374607431768211456 + chunks[i * 3 + 1] * 18446744073709551616 + chunks[i * 3 + 2]);
        }

        out = hasher.finish();

    } else {

        let mut DIFF = 0;
        if (EC_FIELD_SIZE > 248){
            DIFF = EC_FIELD_SIZE - 248;
        }
        let mut x_bits: [u1; EC_FIELD_SIZE] = [0; EC_FIELD_SIZE]; 
        let mut y_bits: [u1; EC_FIELD_SIZE] = [0; EC_FIELD_SIZE]; 

        for i in 0..((N / 2)){
            if i != ((N/2) - 1){
                let bits_x = pubkey[i].to_le_bits::<120>();
                let bits_y = pubkey[i + (N / 2)].to_le_bits::<120>();
                for j in 0..120{
                    x_bits[i * 120 + j] = bits_x[j];
                    y_bits[i * 120 + j] = bits_y[j];
                }
            } else {
                let bits_x = pubkey[i].to_le_bits::<EC_FIELD_SIZE % 120>();
                let bits_y = pubkey[i + (N / 2)].to_le_bits::<EC_FIELD_SIZE % 120>();
                for j in 0..(EC_FIELD_SIZE % 120){
                    x_bits[i * 120 + j] = bits_x[j];
                    y_bits[i * 120 + j] = bits_y[j];
                }
            }
        }

        let mut current = 1;
        let mut res_x = 0;
        let mut res_y = 0;
        for i in 0..EC_FIELD_SIZE - DIFF{
            res_x += (x_bits[i] as Field) * current;
            res_y += (y_bits[i] as Field) * current;
            current *= 2;
        }   

        let mut hasher = PoseidonHasher::default();
        
        hasher.write(res_x);
        hasher.write(res_y);
        
        out = hasher.finish();

    }
    out
}

fn u8_to_8_u1(x:u8) -> [u1; 8]{
    let out = __u8_to_8_u1(x);
    assert((out[0] as u8) * 128 +
            (out[1] as u8) * 64 + 
            (out[2] as u8) * 32 + 
            (out[3] as u8) * 16 + 
            (out[4] as u8) * 8 +
            (out[5] as u8) * 4 + 
            (out[6] as u8) * 2 +
            (out[7] as u8) == x, "byte to bits conversion");
    out
}

unconstrained fn __u8_to_8_u1(x:u8) -> [u1; 8]{
    let mut x_clone = x;
    let mut out: [u1; 8] = [0; 8];
    for i in 0..8{
        out[7 - i] = (x_clone % 2) as u1;
        x_clone = x_clone / 2;
    }
    out
}

pub fn passport_hash<let HASH_SIZE: u32, let N: u32>(preimage: [u8; N]) -> [u8; HASH_SIZE]{
    let mut out: [u8; HASH_SIZE] = [0; HASH_SIZE];
    if (HASH_SIZE == 20){
        let hash_result = super::sha1::digest(preimage);
        for i in 0..20{
            out[i] = hash_result[i];
        }
    }
    if (HASH_SIZE == 28){
        let hash_result = super::sha224::digest(preimage);
        for i in 0..28{
            out[i] = hash_result[i];
        }
    }
    if (HASH_SIZE == 32){
        let hash_result = std::sha256::digest(preimage);
        for i in 0..32{
            out[i] = hash_result[i];
        }
    }
    if (HASH_SIZE == 48){
        let hash_result = super::sha384::digest(preimage);
        for i in 0..48{
            out[i] = hash_result[i];
        }
    }
    if (HASH_SIZE == 64){
        let hash_result = std::sha512::digest(preimage);
        for i in 0..64{
            out[i] = hash_result[i];
        }
    }

    out
}
