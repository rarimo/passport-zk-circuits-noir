//registerIdentity_24_256_3_4_336_232_NA
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
	dg1: [u8; 93],
	dg15: [u8; 0],
	ec: [u8; 217],
	sa: [u8; 74],
	pk: [Field; 4],
	reduction_pk: [Field; 4],
	sig: [Field; 4],
	sk_identity: Field,
	icao_root: Field,
	inclusion_branches: [Field; 80]) -> pub (Field, Field, Field, Field, Field){
	let tmp = register_identity::<
		93,
		0,
		217,
		74,
		4,
		224,
		32,
		32,
		24,
		29,
		0,
		42,
		0,
		0>(
	dg1, dg15, ec, sa, pk, reduction_pk, sig, sk_identity, icao_root, inclusion_branches);
	(tmp.0, tmp.1, tmp.2, tmp.3, icao_root)
}