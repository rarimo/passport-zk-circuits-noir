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
pub mod lite;
pub mod not_passports_zk_circuits;
use lite::register_identity_light;

fn main(
	dg1: [u8; 95],
	sk_identity: Field,
) -> pub (Field, Field, Field){
	let tmp = register_identity_light::<
		95,
		32
	>(
		dg1, sk_identity);
	(tmp.0, tmp.1, tmp.2)
}
