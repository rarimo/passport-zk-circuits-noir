use noir_dl::lite::register_identity_light;

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
