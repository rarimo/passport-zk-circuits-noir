//registerIdentity_25_384_1_3_336_256_NA
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

fn main(
	dg1: [u8; 95],
	dg15: [u8; 0],
	ec: [u8; 261],
	sa: [u8; 90],
	pk: [Field; 8],
	reduction_pk: [Field; 8],
	sig: [Field; 8],
	sk_identity: Field,
	icao_root: Field,
	inclusion_branches: [Field; 80]) -> pub (Field, Field, Field, Field, Field){
	let tmp = register_identity::<
		95,
		0,
		261,
		90,
		8,
		384,
		48,
		48,
		25,
		32,
		0,
		42,
		0,
		0>(
	dg1, dg15, ec, sa, pk, reduction_pk, sig, sk_identity, icao_root, inclusion_branches);
	(tmp.0, tmp.1, tmp.2, tmp.3, icao_root)
}