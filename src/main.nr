//registerIdentity_10_256_3_3_576_248_0_1184_5_264
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
	dg15: [u8; 262],
	ec: [u8; 180],
	sa: [u8; 104],
	pk: [Field; 18],
	reduction_pk: [Field; 18],
	sig: [Field; 18],
	sk_identity: Field,
	icao_root: Field,
	inclusion_branches: [Field; 80]) -> pub (Field, Field, Field, Field, Field){
	let tmp = register_identity::<
		93,
		262,
		180,
		104,
		18,
		0,
		32,
		32,
		10,
		31,
		148,
		72,
		0,
		33>(
	dg1, dg15, ec, sa, pk, reduction_pk, sig, sk_identity, icao_root, inclusion_branches);
	(tmp.0, tmp.1, tmp.2, tmp.3, icao_root)
}