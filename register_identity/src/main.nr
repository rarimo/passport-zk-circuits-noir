//registerIdentity_3_160_3_3_336_200_NA
pub mod test_main;
use noir_dl::not_passports_zk_circuits::register_identity;

fn main(
	dg1: [u8; 93],
	dg15: [u8; 0],
	ec: [u8; 126],
	sa: [u8; 62],
	pk: [Field; 18],
	reduction_pk: [Field; 18],
	sig: [Field; 18],
	sk_identity: Field,
	icao_root: Field,
	inclusion_branches: [Field; 80]) -> pub (Field, Field, Field, Field, Field){
	let tmp = register_identity::<
		93,
		0,
		126,
		62,
		18,
		0,
		20,
		20,
		3,
		25,
		0,
		42,
		0,
		0>(
	dg1, dg15, ec, sa, pk, reduction_pk, sig, sk_identity, icao_root, inclusion_branches);
	(tmp.0, tmp.1, tmp.2, tmp.3, icao_root)
}