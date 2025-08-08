use crate::bignum::{params, bignum::BigNum, RuntimeBigNum, params::BigNumParams};


pub fn exp<let N_BITS: u32, let N: u32, let EXP: u32>(modulus: [Field; N], reduction: [Field; N], x: [Field; N]) -> [Field;N]{
    let mut exp_result: [Field; N] = [0; N];

    if (EXP == 65537){
        exp_result = exp_65537::<N_BITS, N>(modulus, reduction, x);
    }
    if (EXP == 37187){
        exp_result = exp_37187::<N_BITS, N>(modulus, reduction, x);
    }
    if (EXP == 58333){
        exp_result = exp_58333::<N_BITS, N>(modulus, reduction, x);
    }
    if (EXP == 45347){
        exp_result = exp_45347::<N_BITS, N>(modulus, reduction, x);
    }
    if (EXP == 46271){
        exp_result = exp_46271::<N_BITS, N>(modulus, reduction, x);
    }
    if (EXP == 3){
        exp_result = exp_3::<N_BITS, N>(modulus, reduction, x);
    }

    exp_result

}

fn exp_65537<let N_BITS: u32, let N: u32>(modulus: [Field; N], reduction: [Field; N], x: [Field; N]) -> [Field;N]{
    let params: BigNumParams<N, N_BITS> = BigNumParams::new(false,
        modulus,
        reduction
    );

    let x_big: RuntimeBigNum<N, N_BITS> = RuntimeBigNum::from_array(params, x);

    let mut tmp = x_big;
    for _ in 0..16{
        tmp = tmp * tmp;
    }
    (x_big * tmp).get_limbs()
}

fn exp_3<let N_BITS: u32, let N: u32>(modulus: [Field; N], reduction: [Field; N], x: [Field; N]) -> [Field;N]{
    let params: BigNumParams<N, N_BITS> = BigNumParams::new(false,
        modulus,
        reduction
    );

    let x_big: RuntimeBigNum<N, N_BITS> = RuntimeBigNum::from_array(params, x);

    (x_big * x_big * x_big).get_limbs()
}

fn exp_37187<let N_BITS: u32, let N: u32>(modulus: [Field; N], reduction: [Field; N], x: [Field; N]) -> [Field;N]{
    let params: BigNumParams<N, N_BITS> = BigNumParams::new(false,
        modulus,
        reduction
    );
    let mut res= RuntimeBigNum::one(params);
    let mut x_big: RuntimeBigNum<N, N_BITS> = RuntimeBigNum::from_array(params, x);

    let mut exp: u32 = 37187;
    
    for _ in 0..15{
        if exp % 2 == 1{
            res *= x_big;
        }
        x_big *= x_big;

        exp /= 2;
    }
    res *= x_big;


    res.get_limbs()
}

fn exp_45347<let N_BITS: u32, let N: u32>(modulus: [Field; N], reduction: [Field; N], x: [Field; N]) -> [Field;N]{
    let params: BigNumParams<N, N_BITS> = BigNumParams::new(false,
        modulus,
        reduction
    );
    let mut res= RuntimeBigNum::one(params);
    let mut x_big: RuntimeBigNum<N, N_BITS> = RuntimeBigNum::from_array(params, x);

    let mut exp: u32 = 45347;
    
    for _ in 0..15{
        if exp % 2 == 1{
            res *= x_big;
        }
        x_big *= x_big;

        exp /= 2;
    }
    res *= x_big;


    res.get_limbs()
}

fn exp_46271<let N_BITS: u32, let N: u32>(modulus: [Field; N], reduction: [Field; N], x: [Field; N]) -> [Field;N]{
    let params: BigNumParams<N, N_BITS> = BigNumParams::new(false,
        modulus,
        reduction
    );
    let mut res= RuntimeBigNum::one(params);
    let mut x_big: RuntimeBigNum<N, N_BITS> = RuntimeBigNum::from_array(params, x);

    let mut exp: u32 = 46271;
    
    for _ in 0..15{
        if exp % 2 == 1{
            res *= x_big;
        }
        x_big *= x_big;

        exp /= 2;
    }
    res *= x_big;


    res.get_limbs()
}

fn exp_58333<let N_BITS: u32, let N: u32>(modulus: [Field; N], reduction: [Field; N], x: [Field; N]) -> [Field;N]{
    let params: BigNumParams<N, N_BITS> = BigNumParams::new(false,
        modulus,
        reduction
    );
    let mut res= RuntimeBigNum::one(params);
    let mut x_big: RuntimeBigNum<N, N_BITS> = RuntimeBigNum::from_array(params, x);

    let mut exp: u32 = 58333;
    
    for _ in 0..15{
        if exp % 2 == 1{
            res *= x_big;
        }
        x_big *= x_big;

        exp /= 2;
    }
    res *= x_big;


    res.get_limbs()
}

pub fn verify_rsa<let N_BITS: u32, let N: u32, let HASH_SIZE: u32, let EXP: u32>(modulus: [Field; N], reduction: [Field; N], signature: [Field; N], hashed: [u8; HASH_SIZE]){

    let mut exp_result: [Field; N] = exp::<N_BITS, N, EXP>(modulus, reduction, signature);

    // SHA256 cases
    if (HASH_SIZE == 32){
        let chunk_1: [u8; 15] = exp_result[0].to_be_bytes();
        for i in 0..15{
            assert(chunk_1[i] == hashed[17 + i], "pkcs padding failure");
        }
        let chunk_2: [u8; 15] = exp_result[1].to_be_bytes();
        for i in 0..15{
            assert(chunk_2[i] == hashed[2 + i], "pkcs padding failure");
        }
        let chunk_3: [u8; 15] = exp_result[2].to_be_bytes();
        for i in 0..2{
            assert(chunk_3[i + 13] == hashed[i], "pkcs padding failure");
        }
        let mut chunk3_remainder = 0;
        let mut current = 1;
        for i in 0..13{
            chunk3_remainder += (chunk_3[i] as Field) * current;
            current *= 8;
        }
        assert(exp_result[3] == 0xffffffffffffffff003031300d0609, "pkcs padding failure");
        for i in 4..(N - 2){
            assert(exp_result[i] == 0xffffffffffffffffffffffffffffff, "pkcs padding failure");
        }
        // RSA4096 with SHA256
        if (N == 35){
            assert(exp_result[33] == 0xffffffffffffffffffffffffffffff, "pkcs padding failure");
            assert(exp_result[34] == 0x01, "pkcs padding failure");
        }
        // RSA2048 with SHA256
        if (N == 18){
            assert(exp_result[16] == 0x1ffffffffffffffffffffffffffff, "pkcs padding failure");
            assert(exp_result[17] == 0x00, "pkcs padding failure");
        }
    }

    // SHA1 cases
    if (HASH_SIZE == 20){

        let chunk_1: [u8; 15] = exp_result[0].to_be_bytes();
        for i in 0..15{
            assert(chunk_1[i] == hashed[5 + i], "pkcs padding failure");
        }
        let chunk_2: [u8; 15] = exp_result[1].to_be_bytes();
        for i in 0..5{
            assert(chunk_2[i + 10] == hashed[i], "pkcs padding failure");
        }
        let mut chunk2_remainder = 0;

        let mut current = 1;
        for i in 0..10{
            chunk2_remainder += (chunk_2[i] as Field) * current;
            current *= 8;
        }
        assert(chunk2_remainder == 0xa4212add, "pkcs padding failure");
        assert(exp_result[2] == 0xffffffffffffffffff003021300906, "pkcs padding failure");

        for i in 3..(N - 2){
            assert(exp_result[i] == 0xffffffffffffffffffffffffffffff, "pkcs padding failure");
        }
        // RSA3072 with SHA1
        if (N == 26){
            assert(exp_result[N - 2] == 0xffffffffffffffffffffffffffffff, "pkcs padding failure");
            assert(exp_result[N - 1] == 0x1ffffffffffffff, "pkcs padding failure");
        }
        // RSA2048 with SHA1
        if (N == 18){
            assert(exp_result[N - 2] == 0x1ffffffffffffffffffffffffffff, "pkcs padding failure");
            assert(exp_result[N - 1] == 0x00, "pkcs padding failure");
        }

    }


}

#[test]
fn test_rsa_4096_with_sha256_exp_65537() {
    verify_rsa::<4096, 35, 32, 65537>(
        [0xe77c743b021ba95b5bc92e7238d6cb, 0xfcc8ba715ad434acdee85aa73a66af, 0x884a23c5f3d46e77b047c34ee0123, 0x518ddf684a61d6418da43d745e2525, 0x45c3b11b78ed2f3bcfe53ed5479d55, 0x15bf3db2564d54e6b103c2b350a4c4, 0xab72c8254f688ae73b0becdc51fcc0, 0xfa01032c91eee90681b33635ca915f, 0xc6476db7658842be5b006b805a707a, 0x5f19f19847271b676bd094bb1ca440, 0x517ca78b1be61548741ca4a19859be, 0xbf16ee7499c6a70e56fe0c0ecec99e, 0xab4162de57495dd1e6a8ed15f8b5bc, 0xda7ac1f93cd1b6c711330b203ff74e, 0x8d4115837ed1e2b3e686e0ebd1b358, 0xb04d7f1bb3e9f3e2d69f3ba21b1c22, 0x2803b921561201d1fd273ad6af58bb, 0x43308c0582540e0abdcfd30f30f76e, 0x2d7fa111e7f63fd6d3b94a626f81d6, 0x23ecf8594e10067d8ce49ab20d808, 0xfe8e72e0251b3c975e406c9142580b, 0xf239081157721696284ee75289bf4b, 0xb2efafe9225737f857a8d9fe4ab989, 0x9075dd4f8ac2f8708309dc5151f7b1, 0x7247c59617bb469be52f6249502bd8, 0xaf4198100aaa108ffdd3fe359a7057, 0xaf44f7900687192073a5fa1c09e765, 0x2ce33240d648431a12c6af837d3902, 0x66cb133b6dbc5cc668fbcaffbf2448, 0xf5c3938aa320cc3a5fe1c915fad80a, 0xba6e3a94ca35b8b62f7eced35b9982, 0x56ee3424a31cebea82451527cfff57, 0x50496465bd6dea75c24ffefdba8647, 0x1c6d4a375207b772d775d8d5bfe0cd, 0xde5a],
        [0x1432c8439e0c78313bca77bf2b5fb7, 0xfb31f39fb8a66f182914016a4678c8, 0x6c05cb31dd9ac866f19129ce4258e2, 0xf1f1bdb1a27a5762c03840fcd2c26f, 0x7f0b4c29af32009680ce1498f1a8cd, 0x4fb6a5f1a41a4c696da338f432038c, 0x1aa58d92a1ae0522ba4db0fa6abb16, 0x8b9ce4b7ec8f63d934bd1a288dd14d, 0x199fdb0e40ff34eb085a53503700a2, 0x5504fc32945417104d4cbeaa6469a8, 0x234a26ae36e6286ba8cdfef393bb41, 0x3014baecfe115b18cd2b31231dd0bd, 0xe51d7766be18af99bf8ee0abe82bfd, 0xee5935c6b57e90e63dbc830813787, 0x574120140487e5eb2b4902c7695481, 0xff3dc34ecd4fb26774b6ce722351e5, 0xad5fd9a667bd36012041b5ab8067b0, 0xf9ca558fc6f629ec19b51c2482d015, 0xe67bcdfdd9823f4ed207ddcaf537bf, 0xad26861e8db8acdc71c4ca2b91f888, 0xb3a8805d2b7735b51be681871fb889, 0x868bfbade37fa44d7ef12e540fb446, 0xf421ad696b4453644b4bf03a0f6b7d, 0x2434ab2080fb46848c7c81afe8d062, 0x5dc0758a9f9ec269b09842464762fe, 0xb86f39813cc4c3fa2327a8beb96988, 0x3ec7ec3ae304c833b54b48d37a427c, 0xd8a5017853cb3b310e1a6e55131ab4, 0xf74b3884c60032ec7356676b18dda6, 0x7f33684bf61c274d8c2d9bf40a5d37, 0xd0b0b7e803aba138703fae6814e212, 0x9c704e5098b3e1125ff08150de1700, 0x7725afa8f25a28def579112f258d40, 0x89218570f2d94affbdd94e308a5112, 0x126bd6],
        [0x9deb635195ca26e087619dac16fa68, 0x9fddfdcee6beca696681d986b44dc6, 0x79d9de0765cea4d8ecbb40fcead1a9, 0xd9dd67567bbf4e89e667b0398c9c4b, 0x29d90466354ec18c8c7da794f349e2, 0x315cf3a3e9024e105af5bd4d79640, 0x474437f7964995ea5531396565f8c3, 0xf4e932e87c3c36fde5680e5d6e2a6, 0x1553beadc97f978c05b50158a924ac, 0x455de6be99c0169428cd49e59e216d, 0x4217c769db2573878e2e4da162ca20, 0xc88dd07ae95ec69e07fd9d958719ca, 0x900d1c95b06c18baea5fa958e9e550, 0x133e420b303fab010b76793bff9b47, 0x8810fc51a8a49986d99cb18d30e7aa, 0x2deb80a0b2f6577b8a33c6f8f53495, 0x5d44c65053a20443a6a3145152e402, 0xc8cb5e4a6b0f6da5f7b1933485094f, 0x646d7db9fdcff11e0a0849e7fa24a8, 0x3b2b1ce7bc30a42341b4e8e9b5f5e7, 0x73088977569ad95c583652f0f5ba56, 0x4f6e253327197c9058a69edde4802d, 0xe10c2187666ba47f800d71e32a3899, 0xf69b55cf51831d5e33ba168c9731ae, 0xcf7940d6dceb7675ba415f4459465f, 0x5c7a9c99f9a54aff146111738114b0, 0xf52fc06a94026e20aebe2712dbff0e, 0x3b417590d50247b1b51a7631b8c126, 0x4266df081056eea9a967746be78885, 0x8fd2818109e341a006232948d87430, 0x30edae6b32d8f54a922072d5c21d76, 0x799966f82525e6f45078522638e55e, 0x6497bcee11fdedd5f7639544da562b, 0xf6a805ac4af3315192d52a00218862, 0x372c],
        [88, 18, 89, 43, 179, 246, 124, 70, 141, 104, 116, 67, 172, 238, 119, 147, 21, 186, 211, 222, 11, 134, 182, 39, 52, 86, 37, 110, 169, 96, 169, 108]
    );
    verify_rsa::<4096, 35, 32, 65537>(
        [0x6d68b4698ac511b6b7da9a0169a9b9, 0x4ae6cdeb9c7cfbf642b99bb1449e8c, 0xa5c476a7192f40c2be3ba1c994a3aa, 0x61ffdb12dd658d370bef1c70f7132d, 0x1091a758a83ad919ced7b8207a3006, 0xca4a4888e88dbfbdd656bfe0ca939, 0xa6ad07ef573ec605b971df139e968c, 0x477384fa7f89a36cc00dc540f2af7a, 0x2f1a08e93c63a2b21aa26a04d4ac1, 0x96aae2448165911878b7fc90772ea2, 0x257298e10a9f2f7ad0ae6f882ae1b4, 0xea4c83e7b69bcd71254e40766f9c4b, 0x3b6d524945b4091267784a1c4bad54, 0x39a35a5d06e56389b7a40a9cc5bb89, 0xf3b24510f8fb48d06b25a8fa4d9304, 0x6743c992d7bc528b3f87944502976d, 0x8bcda8f5ce6c8954892bf739fdbace, 0x73c34990e27a32a8fde8640ef43dc9, 0xb3207931fc386f086d84bc97a26edb, 0x72a4ae5604cb4d08bfbb6b24208a1e, 0x6af88ced7a88dd36de1c20fd29e3d8, 0xcebf6e5b3228e6f45a69bff8915cde, 0xe75a3b1669a30c81194da41323b604, 0xdd057a2c570de5eebee118bb036e4e, 0x1df2627c409abc327242c8ce053d7b, 0x427bb716666a7789bc6b3b1415f366, 0xfbbe88441536c5f1e7ed3be82f6e14, 0x5c6ab23ab69974aa8ca0a5139631c3, 0xcedcd8882f90ae4e026238aa2f4497, 0x7862da139efc63e3627ddc1ca7b94c, 0x16cbcf7522aafd5a6cf4346b204e68, 0x9424df11ebbc04602478a01a632326, 0xb39d909c16b2dd3db9f9a9eae919b6, 0xfffb4f63c013bdc22497ce0952f151, 0xbd33],
        [0xfb3e56cbbf6c281d5f7af8e98435a2, 0xda827e9a228c28e4c3005cc45287d7, 0x618aae8844658e57cc78f0ba4b5a78, 0x98c5f7efa99ab32943e2c8467143d2, 0xc48ca894c52d19c1eebfe6c4a3e04f, 0x29674081d421cee2c6e433c00e7e21, 0xf000c313736ff0045e43443215ee26, 0xbd83db74a444ef1cc4c8b968c15ec5, 0x42d3534764c1028e318311e6f0e371, 0x410714e9d62cba516e9bb962525a75, 0xc9333ef83fcb8eae6dc955571f00dc, 0xda624bd118730bb5bd91b87bd7ec82, 0xd94ae0d6a9a9389308328e43dfa7f2, 0x7d35ec56214b505e249767fac40c5f, 0x2c886e70e6049465b5e24655f574c8, 0xed48b7c5b41b8384ebd53f64e85ec6, 0x8bfea059ce47cf12eb1d77c4af45fb, 0x3613d976cda1d6d493ede48135b465, 0x6e4b020a0423c9a69d99f8e7fe5345, 0x7b176df0dfd5bb695508c264b07ddc, 0x9e1e3745ee934daf5c46e564be0169, 0xe5a0b5d50a4b5f919c3392c05f7911, 0x655d7f70f884954e9cd58b24760a96, 0xbeba2b519351f6e95ee5257e5f73bd, 0xc4e9b3e253ac751ff214076da173c4, 0x204b9720cf6f89807cd9a289ab269e, 0x44c3c29d46f3b59d155ad9b10c4cc, 0x1853980047f4800398720412bfd4d4, 0xcae65eb24168f11aa39f3833e447b4, 0x775056c46b49950191ac1747c40755, 0x9bf0981793d33f5151ef710a2c6f93, 0x737e4dbb158dde3c1c81d432ccda90, 0x3ee72f3cfaa9c96b7b4d871cd8b240, 0x9e81211151df89b25abaee883ba229, 0x15a610],
        [0x3f5ea966f7c83f202048d2605712e4, 0xff5c546e3bb637fb6cf6c3f9dc29ca, 0xd8ffebd4ff7f8124b008a932feb051, 0xfb64a1e9c97bf71ec7291fd59eae2f, 0x60c04b7f97652026396f7391eae6d1, 0xfb4e189e77b975932d3492853f6e9b, 0xdae7aeab1459e20fbc11c04712d2ba, 0x280e90ca3189a3fe3e684f675e4d26, 0x98d71e5acc8c5af425b8cdfeb29ba0, 0x2da3c2e94d2d9f87f861dc95d6885d, 0xc0e7530f9b364cc3a5f53b2be0be77, 0x18a7baed1cd38832b14a4e3b26c47e, 0x4ec465303e704f23a1c48c83e1b8f0, 0xbcf42c0052d68dc4051dcd560951dc, 0xa70fbcf80f73416043610b1017938d, 0xe508457bf3cb774b05f7b4a480364c, 0x666d02a253b2c505248b5f782ec771, 0xbc49671cb8de94bf6395be6ebf2bf3, 0x9de4fb283ade1b96120dbc2af12960, 0x27213ffd2c046cede8b418f4a6091d, 0x5056f860c9c2b776e4fca0f9cee4c5, 0x8083968b291f7e4ecbe4095ddbbd40, 0xabd312c7eec98d9a63055d574718ad, 0xb0e7c87072f866079ebeee5a01e0d9, 0x991ea28326de40cb4f19d224c92e4f, 0x31d3f75208af88446d2c1773e6587c, 0x97404794b604b36440d88d3d6ff389, 0x7350163061bc03f31764218b090282, 0xf3c2045f35be017c2aa6f48925ee21, 0x5bf63bcf2d729aa8caa72d7024809f, 0x7c79375a5f5bb2f5d3daeca486f90e, 0x87e0c72addd8eda7b675ed98ee1e3d, 0xeeee0506fb8d3bee66d695523eebc, 0xbfd5aecdcf550b468a829df4d5bdb3, 0xaead],
        [217, 163, 66, 196, 3, 140, 5, 66, 92, 243, 196, 50, 30, 3, 86, 176, 183, 95, 121, 80, 202, 134, 100, 123, 27, 95, 228, 189, 223, 178, 253, 8]
    );
}

#[test]
fn test_rsa_3072_with_sha1_exp_37187() {
    verify_rsa::<3072, 26, 20, 37187>(
        [645909875064429653479306659449746391, 747691862747664245828950192993549827, 738741595263523084577797034128793938, 136840989167614306708098295069960373, 106247663819017131526353923228753652, 508161778586909989302906770029017090, 648875142605545746339689165139639154, 230873877929376499020969767963465528, 609883079518410152277110529455072039, 144576461785036140445031619936221657, 1225187739121137366590592989060017162, 889273617989368956193354500425911067, 980951430204472511327838327381035800, 768287743713505739420748287549227311, 1315293902206702606646440217609109651, 890987243334359399481358310215697291, 11092374468564772053578612277786178, 797012421031426413966825656165896929, 264940066454386617381250469263996565, 5364827332290389539340136807729527, 526183018186147583598624748142571409, 602855137596090621557292605937961014, 690876362652483529041903401601497974, 271070178837657715221958096386204784, 917357720822967140607095474901939278, 4288552158832764774853],
        [0x7a09f8edb308f7f55db8ed8a2f861f, 0x22acd902f5b094690e46d36de67ac6, 0x3356f00c309b3195d8d888ae944e83, 0xb62a1a72aa2059b87d1b286245fe9a, 0xc8863b93a0ba55071dd9b9024ca042, 0x27d0b2f8b968f0590692d0529ce8f3, 0xf09ab0fce58089460ff9be1abfa410, 0x547d947c31aa693c1f3bb5e9529286, 0x2899b8b250f6706f4a60354c54903a, 0xb578902c7cfbffe777c7cffa5d587b, 0x7c1cee8e7769c5f03b00adbcf76ada, 0xd04f09e966ac2429d529d1d826466c, 0x5262d57d3758c0a77b8fcb3b944d06, 0xba44e68b174986e4275200218d1a70, 0xfa2da7e39984ae18c67b9b8555dbf3, 0x76f7eeeceebfce27a4b3f5531ffb1e, 0x4b263cef1a4e4adfabf101a47dbe9a, 0x25094d280e8dde564594219d717ce7, 0xf85e20f697c854ad5b50a68ff0fe1f, 0xdd80182888de6183fd5343534057a7, 0x2186d1cd51bccc5b9b7a78b44d7aa1, 0x9d53690449028b375bee19e6669d2e, 0xc7587f4f18fdbcbd0c4ba0053bd395, 0x5393ad9393c2294e932d9f0470b2d, 0xd34c30957b637d21f7c5cde11b8ce9, 0x119e56217f5668939aae],
        [645100392534006315745213569264403478, 1238021370270860021484473217215104033, 765170968967597021438818428030822258, 980620731859655363308062784793350984, 952212258366910253667331401474641691, 96769503189314089802564320513739032, 1280190838328392882898472633953135978, 334912814255695975277248797223925565, 828565387341838298017854563599600528, 574419414864413491602308305997747018, 455350897444347631638740831894125474, 1011440729643150773589989033855359773, 97598530307013003612631613265773812, 11309564190321757631496035382436130, 291678019205924535036853494160015237, 814425155869888359243926427918080235, 148373891482766818600107620844806194, 411036755146441325752845628757695425, 84120798859938932504147191730213954, 56211343416358852424363272721119057, 478414206377403439481534249083649847, 193000686832595368150144854590959400, 693895659669846929042195864450042691, 1177018250193562585403336244084710852, 1156962266876048303140299511580288967, 2830924758566856359584],
        [78, 61, 214, 7, 10, 192, 88, 40, 194, 109, 122, 73, 179, 66, 236, 37, 184, 13, 82, 51]
    );
}

#[test]
fn test_rsa_2048_with_sha256_exp_65537() {
    verify_rsa::<2048, 18, 32, 65537>(
        [0x687aac475b38443456d0e225ad6cb1, 0xaae45172ec57b0ea2a0706423d4eae, 0xe61df68eb79a279594840d74d37fd, 0xea6969912d17b0e2efe2cc1abbcd74, 0xd31dc1880015b31dc2707d58a73f2c, 0xc43b058f3c4ec15fc951259a8f8d1, 0x7e0a5e62adada228e19e8543c48031, 0x114b7c9deeb7b7b98d9c9cbb7bfb28, 0x4f2f01f5ecffcdf3c8ac793da1d036, 0x3f1c96a9e8b61cb72cd54d842c207b, 0x4a4303dab1c47931af4af4939ae7fb, 0x43b184bb2fc334a002056e4fa1d2d8, 0xa8a796849be0659aadc955ebfd6e1a, 0x9e033bc8f2284a0d8856adf18c7bcf, 0x550385d4a541ad6b055f2964a1105a, 0x6035885337422f5fc78d787ceb1de7, 0xae0123c781a9dddec07e956eda70af, 0xb3],
        [0xf7a53b87adbca3754e37b29832cf65, 0xb6f66d917ead2a1a9ee6d98dbc1b, 0x2fb1691a74375fbe05c06da2b25fcb, 0xe9b5b77a14268be6dd04f0819ac99, 0x4eca8d499c0d0c29cd90b2d05a9d8e, 0x213479801d26c9cca9ed2b048fa84, 0x7690870c11f5f1f117dbd13810d3aa, 0x81fefcf214735e5a470a2c4e0378d1, 0x2dbb8e6501ec054e628a4a5f19a768, 0xbd090b556ffde28c1f5fa783320ef3, 0x7fe70ed326c6f1666b160e2dd9c657, 0x9a7fd440035d8531adfd3e3a54cb44, 0x8bb9e81a8652606b248e9689ab624c, 0x4f75772d1970ca0a591fb2e74fbea0, 0xec94027e5a9823b713a1cc684fdbf0, 0x7c43439242ac07b200e7de8fadb600, 0xce7a884437cd576d4f89e2ee6fa1e3, 0x16cb],
        [0x39c4223c65218597977988ba479309, 0x1f78ba8e01d121e9e0ccbe4b006111, 0xc33f753f7ffea78b8faf89b50ab256, 0xfbed4af442c0376ca812ebe6fcaf9, 0xce3d68a82c9d97fe99eec4d32a8ad5, 0x2076f300ef341c3d6b52cb2f3bbaaa, 0xfbce9fcb33bb65ccc7b9340bf41314, 0x2fdf02f01648bd56c0ab41b4f177e8, 0xe8663c0872a4a6b2779222dfb57dab, 0xb55600050199a2b708dd49167e2a72, 0x514abd30dc7878c3d5d50c51e9b5a0, 0x70ee10ba84daf65ab0e2684b17279b, 0xb1a041f056a053c8feac36960af603, 0xff4dabc27ceba5385b97886a1b5e89, 0x1ae74a1467adc8631a9f62e42e1f49, 0x2b1baf60769ac2a702102b9f47025b, 0xc6e311e9613b3d449ac5b5d860666e, 0x3e],
        [229, 3, 55, 5, 77, 184, 13, 123, 92, 196, 6, 222, 244, 163, 125, 160, 193, 25, 217, 187, 222, 47, 60, 141, 69, 133, 237, 250, 87, 183, 207, 54]
    );
}

#[test]
fn test_rsa_2048_with_sha1_exp_65537() {
    verify_rsa::<2048, 18, 20, 65537>(
        [0x9c2614044ef71e9c5c21ee4152e3ef, 0xf83ea602e40bff5b5d4a10ae1c2dbc, 0x21804881fa12d3c6c69cd77a7c24a8, 0x2c5a18ee951656b7092665093b4f00, 0xc96413f38cd893ddc54b78a333c180, 0x719cf85b6b754cb5661972aeaf3749, 0x64f2322faa3c69290b83fdae532608, 0xb72a19f61a1cbaf3a895e33bc180f2, 0xe9509e95a39a8f051487e21ccd95fa, 0xc0a8086ae70fd5a8d61e6cd71a5977, 0x468cc75d3ae6359d5e700cd9c1a0e3, 0x2d760ed3e89222a8d575166edb3ff2, 0x3c911c8ef4969316ebacba668932b9, 0x73c29b41590bcb1ee5e26a3ff9f5e0, 0x2bcedf7d0e93618138ada7435dd97f, 0x2c1c973fc26c5f513e7e69206125e0, 0xa93fd88247bfcb7ae63615a0044153, 0xbb],
        [0x33ffef9fcbdd977fdbcb517eac7839, 0x305062d19651219ff346887a5c8c86, 0xcfe501595ba3418427ba854a747cd3, 0xb33231aac925007c720d4dbc0330b4, 0x6bf0a7e4c33f263ab0bd8239aab099, 0x7304b3c8e2e548ff44b8c0a198040b, 0x15568d65aa3c9550adf7847bff2978, 0x4d7449fedbc9e0d380963b2bd8c387, 0x72f91e069edec493fb130bec728932, 0xf7cdb72fe761f4cecc0ac96d136c82, 0xaed53c695cccbbc957cc920d49e9f7, 0x55b817abff41423553e6a40710fd72, 0x5a09f2cc58636214af9a9705168720, 0xcb942843a969572c60ffff15bba188, 0xe815461eedcbb9266c208421404f91, 0xa7bbb86344c47ee8ff0f2e6ac06ad6, 0x9a82b0ab7d518911f89d7574c0ba09, 0x15d3],
        [0x3dccc7cd59d257cd326e0656e39446, 0x6e5de16e9b014d16167aebc5a25feb, 0xdea04d0f8e29b3060c9289d9ac3abf, 0x13e361e7170abe9e60b83d47f63113, 0x4c9f22eff1727c0c3b2938864a758c, 0xb79927d906745b823b56b95a9be7a8, 0x4a278ce741a81bf16a403f993e33c1, 0xd7f016dd6b29827bee26005f34ba92, 0xdde35ab002f959039077666a45b781, 0xa7334ddee9cbf0d9b16448f2036c89, 0x1c40be58fda59e5f57c372177dfc2b, 0x9ae1951de629edb05212db8669bc9, 0x5a313d22853283f99defc6ec9f364b, 0x3d1d756cf9b1342eb263cb14c60291, 0x28c484da7eb0af37ae7cfd7a2ac9a3, 0xa42af8b52c38d736f7d1ee0af8ff6e, 0x40dda9b31972da0559245525cc3327, 0x5e],
        [163, 254, 223, 86, 65, 164, 105, 250, 229, 239, 225, 197, 163, 96, 62, 207, 35, 201, 229, 252]
    );
}

#[test]
fn test_rsa_4096_with_sha256_exp_65537_2() {
    verify_rsa::<4096, 35, 32, 65537>(
        [0x44146052f2836ae8310a53235451b7,0xaf1c68ffac6c4fd9a3f432c61429af,0x83a98e088d74716dba88f07ab5c320,0xef3f7aec282bfd1af4cc0e9c5a220f,0x63e7977928f513c2185c40f5d687ec,0x3fba5bbfb442dcae851f89aed4b5c0,0x53f51cf9409aed874debf4e5632690,0x711c83a9bac739f2c5e664ceca50df,0x6011a730b5ac5c261c8adbe9bbcdcd,0x97ae0b9f7943f4892c7cc4e8c22116,0x438ba3131b30c37e516d82231a4857,0xa25eb7e110a676313a8f134c1c92bf,0x501df37f4d5709d2fdba10669e57d2,0xad60450e42c71d1776a866221ec65,0xf7dcf449d0a8d8035cc4075aadfdc7,0x8fe6649f33b0a8eb20ac6918f15769,0x9c0a8b53a940148972af7a5ed14002,0xfee7c028c5bfd22ed84c9972cebb9e,0xc2b11484d02e12a97711645667034b,0x9b6940d1805cb581854898a6063403,0xa6491182831e9a8ee7f365e3cea530,0x352a2ee89aaea4646aa3d3fd8dd2a9,0x6f3d60d5e6aa15a21e2db64afafa64,0x2caa106c2b65e24d2b1a4617175fbc,0xa34aa4a84d5d9e4acfd117c772980c,0x9b46cc60c2983b3a47dd82080e5512,0x6227928efe49fbb9642ad1149e7f7a,0x272a12e9d6545d72efefac7f8f3f1a,0xeb57effeef84ce112fc1d2dfc62e1a,0x79d5a5e571aab21d94ca48e40fe2ad,0xae40fabb3627d341691b2d7aee46d3,0x6f9afa670278fb4fb20d8b974f550d,0xf30a3db3b2d3b867af4ace8b061bfa,0x2f9d1e0dfe98ed2d4b39a57f536085,0xc805],
        [0x33a03da8f4226d8e49000f6e2ec095,0x334dbf745fe725735c07a5865e0bba,0x6e02f5a7b363b56ce23cf4c77b20e7,0xf3ccd1e9f8d487ded087c3711799a4,0x12c3c525ae9527f02a195eefe28c03,0x2568cb2c5927c713641bfea26e395e,0xe8a25a1fb3c9318666396f4574eb05,0x54acb57ca7e502335bffdbfd5fe2ce,0x116109a4c48bb3cc4cc91db48bf799,0x3767f89f79efce4c5370f9aa14ca1a,0xfc0d42b6ab0b63a497e6b38f8d0c94,0x45693159b39ef2c8622e1876270dc2,0xea5c1de2003aafab10fcbaf7ef3c7d,0xb683e0397ecf6a3035bb8c7dd8dc98,0x3d68a7834cb21a6e3a05eda2dc9f65,0xe1383c35475d20aa1f4e970879af49,0x71790babe58bf625f99af79d369bfa,0x14bae8b07a407ff3ba6af90e065f71,0x863042e7b151eede35d5ed06d8cc02,0x6bde79c44413e60a205e63bf73003e,0x80e3c307999a441efdb95b127380b3,0x83c3d2b4657e121d46eb10bb3754ae,0x205da7fde1f550ab669a131a7e788f,0xc6621ffa58502b363165597080d54c,0x4ca1e35076b26855b3f0292c1b486,0xca1434eab45b0bfcef9eaec7630e9d,0xc03385c0c9dc4ba3a66404b365e1da,0x9bbddede1e2c6f2f5be2d293c59ccf,0x5f2f5321f4e7c9007fb16defcaca61,0x8f6bf4121893f003e85287f9bae3c5,0x25dafea6a159c636eb1b6ee3ffd2d9,0x94c2b40efeb403647768ba40ea47d0,0x89ac48092b873aae01772dec771d66,0x589b6d5ea41a119b8c6ec8b0cfe758,0x147a59],
        [0x582a422f661c5defb32bbc83d1d438,0x7882a10c50968cb0558f371f4f147b,0xf6f9772abcdee80fe1b9a1d159aa1d,0x1219ba2e440cc09f9b88154b8a4451,0xdbe40572858f3f0fd551ea4084af0d,0xdfb23c9ce5f42155507645ebbce5bd,0xab64c53eed2c1d0aac7b630d1624aa,0x4ee5a57d744b76cb3be3c0c62e3a88,0x943bcdec1ab00bb3e7aa49ddf8d588,0xd37a23f76f5d1616dfa1613867f84c,0x3bedcab455ed77452812b2f730052a,0x6eff9169a2021d2a1e18f52fbdfcf3,0x313a95412542a1a41ad0160e8a2be1,0x110f336640aa9ce610d57a396e2c6,0xb92240fbd8fd0a58b28fc942dc1bb7,0x7899799f0f30506deac8f7520f1d5a,0xe115ec6d43a681d4b5115cb7e8c8b9,0x2b46ae21b78296108b70eaf3951285,0x767cc4f1cc008994c729bd5af72e02,0xf1ad817ca5e52de389f0f9f4d3ea90,0x9c536a4930c5da2c0956071d015b93,0xf915f1dde14a1f72f52406ef5feb5c,0x1289813e16fb3dc395879d50fad6e1,0x4bfec961b1c0903f08574238fca569,0x75942a0485b244af42d955dcab5ea9,0x3475e9e3861da23015847841ac9b3e,0xe25ed469d91d35fc12783d16e6efd,0xc803106e6ed01834a4931188c4338f,0x34d7f408b7a1ad86140f17e8db8691,0xba74bf5071bc9a42cb2109633a6d22,0x1c4b638cfd8b34bf2fa75c5c5f1e8c,0x5e2bcfbbb822b235ab56e6635a9c33,0xa2d914cec2da98f0c36d63187400c5,0xd752b7d701b85c32a931be0f603543,0x4f7b],
        [233, 3, 21, 106, 152, 15, 253, 148, 177, 114, 182, 202, 122, 96, 116, 31, 122, 15, 4, 215, 47, 88, 148, 68, 100, 24, 223, 42, 52, 118, 16, 23]
    );
}
