//registerIdentity_7_160_3_3_336_216_1_1080_3_256
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
	dg15: [u8; 165],
	ec: [u8; 155],
	sa: [u8; 62],
	pk: [Field; 26],
	reduction_pk: [Field; 26],
	sig: [Field; 26],
	sk_identity: Field,
	icao_root: Field,
	inclusion_branches: [Field; 80]) -> pub (Field, Field, Field, Field, Field){
	let tmp = register_identity::<
		93,
		165,
		155,
		62,
		26,
		0,
		20,
		20,
		7,
		27,
		135,
		42,
		1,
		32>(
	dg1, dg15, ec, sa, pk, reduction_pk, sig, sk_identity, icao_root, inclusion_branches);
	(tmp.0, tmp.1, tmp.2, tmp.3, icao_root)
}