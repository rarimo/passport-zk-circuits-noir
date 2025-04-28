//registerIdentity_3_512_3_3_336_264_NA
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
	dg1: [u8; 0],
	dg15: [u8; 0],
	ec: [u8; 310],
	sa: [u8; 106],
	pk: [Field; 18],
	reduction_pk: [Field; 18],
	sig: [Field; 18],
	sk_identity: Field,
	icao_root: Field,
	inclusion_branches: [Field; 80]) -> pub (Field, Field, Field, Field, Field){
	let tmp = register_identity::<
		0,
		0,
		310,
		106,
		18,
		0,
		64,
		64,
		3,
		33,
		0,
		42,
		0,
		0>(
	dg1, dg15, ec, sa, pk, reduction_pk, sig, sk_identity, icao_root, inclusion_branches);
	(tmp.0, tmp.1, tmp.2, tmp.3, icao_root)
}