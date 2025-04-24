// registerIdentity_21_256_3_4_576_232_NA
pub mod bignum;
pub mod test_main;
pub mod sigver;
pub mod big_curve;
pub mod rsa;
pub mod sha1;
pub mod sha224;
pub mod sha384;
pub mod rsa_pss;
pub mod jubjub;
pub mod smt;
pub mod utils;
mod not_passports_zk_circuits;
use not_passports_zk_circuits::register_identity;

use sigver::recursive_curve_proofs::recursive;


// fn main(s1: [Field; 4], s2: [Field; 4], p1: [[Field; 4]; 2], p2: [[Field; 4]; 2], index: u32, prev_index: u32, table: [[[[Field; 4]; 2]; 4]; 4], verification_key: [Field; 115], proof: [Field; 254], public_inputs: [Field; 161], key_hash: Field) -> (){
//   recursive(s1, s2, p1, p2, index, prev_index, verification_key, proof, public_inputs, key_hash)
// }
	
fn main(verification_key: [Field; 115], proof: [Field; 93], public_inputs: [Field; 161], key_hash: Field) -> (){
	std::verify_proof(verification_key, proof, public_inputs, key_hash)
}