//registerIdentity_2_256_3_6_336_264_21_2448_6_2008
pub mod test_main;
use noir_dl::not_passports_zk_circuits::register_identity;

fn main(
	dg1: [u8; 93],
	dg15: [u8; 315],
	ec: [u8; 338],
	sa: [u8; 74],
	pk: [Field; 35],
	reduction_pk: [Field; 35],
	sig: [Field; 35],
	sk_identity: Field,
	icao_root: Field,
	inclusion_branches: [Field; 80]) -> pub (Field, Field, Field, Field, Field){
	let tmp = register_identity::<
		93,
		315,
		338,
		74,
		35,
		0,
		32,
		32,
		2,
		33,
		306,
		42,
		21,
		251>(
	dg1, dg15, ec, sa, pk, reduction_pk, sig, sk_identity, icao_root, inclusion_branches);
	(tmp.0, tmp.1, tmp.2, tmp.3, icao_root)
}