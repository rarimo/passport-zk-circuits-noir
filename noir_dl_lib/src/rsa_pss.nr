use super::rsa::exp;

pub fn verify_rsa_pss<let N_BITS: u32, let N: u32, let HASH_SIZE: u32, let SALT_SIZE: u32, let EXP: u32>(modulus: [Field; N], reduction: [Field; N], signature: [Field; N], hashed: [u8; HASH_SIZE]){
    let encoded: [Field; N] = exp::<N_BITS, N, EXP>(modulus, reduction, signature);

    let mut encoded_bytes: [u8; N_BITS / 8] = [0;  N_BITS / 8];

    for i in 0..N{
        if i != N - 1 {
            let tmp_bytes: [u8; 15] = encoded[i].to_le_bytes();
            for j in 0..15{
                encoded_bytes[N_BITS / 8 - 1 - (15 * i + j)] = tmp_bytes[j];
            }
        } else {
            let tmp_bytes: [u8; N_BITS % 15] = encoded[i].to_le_bytes();
            for j in 0..((N_BITS / 8) % 15){
                encoded_bytes[N_BITS / 8 - 1 - (15 * i + j)] = tmp_bytes[j];
            }
        }
    }

    assert(encoded_bytes[N_BITS / 8 - 1] == 0xbc);

    let mut masked_db: [u8; N_BITS / 8 - HASH_SIZE - 1] = [0; N_BITS / 8 - HASH_SIZE - 1];

    for i in 0..(N_BITS / 8 - HASH_SIZE - 1){
        masked_db[i] = encoded_bytes[i];
    }

    let mut hash: [u8; HASH_SIZE] = [0; HASH_SIZE];
    for i in 0..HASH_SIZE{
        hash[i] = encoded_bytes[i + N_BITS / 8 - HASH_SIZE - 1];
    }

    let db_mask: [u8; (((N_BITS / 8) - HASH_SIZE) - 1)] = mgf1::<HASH_SIZE, N_BITS / 8 - HASH_SIZE - 1>(hash);

    let mut db: [u8; (N_BITS / 8) - HASH_SIZE - 1] = [0; (N_BITS / 8) - HASH_SIZE - 1];

    for i in 1..((N_BITS / 8) - HASH_SIZE - 1){
        db[i] = db_mask[i] ^ masked_db[i];
    }

    let mut salt: [u8; SALT_SIZE] = [0; SALT_SIZE];

    for i in 0..SALT_SIZE{
        salt[i] = db[(N_BITS / 8) - HASH_SIZE - 1 - SALT_SIZE + i];
    }

    let mut m_dash: [u8; ((HASH_SIZE + SALT_SIZE) + 8)] = [0; 8 + HASH_SIZE + SALT_SIZE];
    for i in 0..HASH_SIZE{
        m_dash[i + 8] = hashed[i];
    }
    for i in 0..SALT_SIZE{
        m_dash[i + HASH_SIZE + 8] = salt[i];
    }
    let mut hash_result: [u8; HASH_SIZE] = [0; HASH_SIZE];
    if (HASH_SIZE == 32){
        let hash_result_256: [u8; 32] = std::sha256::digest::<(HASH_SIZE + SALT_SIZE) + 8>(m_dash);
        for j in 0..32{
            hash_result[j] = hash_result_256[j];
        }
    }
    if (HASH_SIZE == 48){
        let hash_result_384: [u8; 48] = super::sha384::digest::<(HASH_SIZE + SALT_SIZE) + 8>(m_dash);
        for j in 0..48{
            hash_result[j] = hash_result_384[j];
        }
    }
    if (HASH_SIZE == 64){
        let hash_result_512: [u8; 64] = std::sha512::digest::<(HASH_SIZE + SALT_SIZE) + 8>(m_dash);
        for j in 0..64{
            hash_result[j] = hash_result_512[j];
        }
    }
    for i in 0..HASH_SIZE{
        assert(hash[i] == hash_result[i], "rsa pss signature verification failure");
    }
}

fn mgf1<let HASH_SIZE: u32, let MASK_LEN: u32>(seed: [u8; HASH_SIZE]) -> [u8; MASK_LEN]{
    let mut out: [u8; MASK_LEN] = [0; MASK_LEN];
    for i in 0..(MASK_LEN / HASH_SIZE + 1){
        let mut preimage: [u8; HASH_SIZE + 4] = [0; HASH_SIZE + 4];
        for j in 0..HASH_SIZE{
            preimage[j] = seed[j];
        }
        preimage[HASH_SIZE + 3] = i as u8;
        let mut hash_result: [u8; HASH_SIZE] = [0; HASH_SIZE];
        if (HASH_SIZE == 32){
            let hash_result_256: [u8; 32] = std::sha256::digest::<HASH_SIZE + 4>(preimage);
            for j in 0..32{
                hash_result[j] = hash_result_256[j];
            }
        }
        if (HASH_SIZE == 48){
            let hash_result_384: [u8; 48] = super::sha384::digest::<HASH_SIZE + 4>(preimage);
            for j in 0..48{
                hash_result[j] = hash_result_384[j];
            }
        }
        if (HASH_SIZE == 64){
            let hash_result_512: [u8; 64] = std::sha512::digest::<HASH_SIZE + 4>(preimage);
            for j in 0..64{
                hash_result[j] = hash_result_512[j];
            }
        }

        if (i != MASK_LEN / HASH_SIZE){
            for j in 0..HASH_SIZE{
                out[i * HASH_SIZE + j] = hash_result[j];
            } 
        } else {
            for j in 0..(MASK_LEN % HASH_SIZE){
                out[i * HASH_SIZE + j] = hash_result[j];
            } 
        }
    }
    out
}

#[test]
fn test_verify_rsa_pss_2048_e_3_salt_32_with_sha_256(){
    verify_rsa_pss::<2048, 18, 32, 32, 3>(
        [0x7f232ace937aabc0932a887aac8115, 0xdc0c7707235e570452e9e531183b62, 0x55bc1032b5b748248f6cab4d5111c6, 0x7643d28cd8cf91beee2900cc1dffdd, 0x400d73470621e2ea742a62018ee01e, 0xfcc340fe4dbed62fc91b99594a5a51, 0x5b6f8854fcd9f4888a69c3e2ac4183, 0x24e09dcdf7470b5f813e0316ee2101, 0x8f3cceb888de40b59ac92fb86e88c6, 0x21bcebd54e7575f1bfff08dda04429, 0x6fde1fd66696dd25c5a37cb9133b52, 0xd93f9f27037facf8ab11729ef6ab2f, 0x4798f867e82154794c18f8d1c679f3, 0x58183ba450972d8a7223599ffff9a0, 0xd56cdb3b432e123880859d275786c0, 0x976020ce63f50f8b6ee5e3580dabcb, 0x9d70b1f36fa5e58d0a97d2a1a09186, 0xde],
        [0xbf34dd3fb43baca2f6cd6b3cdc6699, 0xfbcdb44f57b9de329df22e8268dd16, 0xd9712439ff9fd3a614e3c56e1c9dc3, 0x484196ccf523859e25ebcac3377dfc, 0xe02f4fcdf5ad16a0808a9a43b8c130, 0xe646290c1d2d2909ecd5be4bc930a3, 0x90e32a3a3fba7b43ae2fbefa9eb40f, 0x97ab601dc9fed2b0280e6706f6d201, 0xf58bd45c38dca3d6972b1165a9c3e9, 0xe0b0b44dd9c9d35a5e1c3b541b40e6, 0xfe98327c8f5b6cefaec41f96c4e6f3, 0xdcaa457be67cf46b899f408eb5e8a5, 0x7e1b3fafe7b4e190cb20cea1188a57, 0xb36aef45208d90222b134c2ecb8583, 0xe1256df1050b97470a81360de49b69, 0x7b6042dd2a1996ea594a8964a238e7, 0x443efa98c4226645737345bb03657f, 0x1266],
        [0x2486432e448059337f1c3bb002df96, 0x44bbb431454faf89be893ae9a08b2b, 0x2f9663ce851519e7168f368252323a, 0x2b60a073b6f4c22313e83a7e91c43c, 0x940772d8a0cd4c8d6d9ff41a9fcf28, 0xb3e135751a3cd4cfd5ad8edd2bb67f, 0xa8fe2b0a0750adda229616861998a0, 0x9d7a90bd7f7697cd248550e7649820, 0x89924a0129e5a7c0b168ad0d3d720, 0xe730678ef64f884a39752779f34ecc, 0xcc34378ca999e3c0449b4fa0bb6fef, 0xd70da5b96d3b79d5bddb2fe63560a5, 0x9724a95c956624153b9fc1fdc79ceb, 0x29162c10908c0e6a6ee874e5a6c502, 0x6a6cd952dbf031c60d1cab8313969, 0x33122b3f63d823c038919ae0a95e56, 0x79853f2e32b064cb55dcfd3c67bdbe, 0x93],
        [176, 203, 20, 93, 162, 86, 247, 63, 229, 196, 30, 128, 142, 222, 41, 235, 95, 74, 116, 89, 187, 244, 15, 178, 99, 215, 251, 235, 215, 119, 239, 173]
    );
}

#[test]
fn test_verify_rsa_pss_2048_e_65537_salt_32_with_sha_256(){
    verify_rsa_pss::<2048, 18, 32, 32, 65537>(
        [0x80b0e4157b26640c569ae477e04f19, 0x8d3d49a68b60e5c89c5152ad6e7f04, 0x1703e7a112602cf8fbefbc329afc1, 0xd20daa5e8e114204661a3d1f21650d, 0x34b2d8bfa513fcf5788c0569e0527c, 0xdc3bdb0442ba550cde8355194c3c39, 0x64de493ddae79014ed0e6fcaa2ca4c, 0x8f782fa2ea942118379833bec37cab, 0x5684dfff2d21a85cb73bcb32ac172c, 0x8c59f18fe1f32e6c328b64f58f95e0, 0x66b46fb16ece1372424d3aa3b97542, 0x8cff2e2f574ec92430202f5dafa6df, 0x4ad1e7fd05c573c053e04660fd3112, 0x889763afc2b68e66b5928403d50872, 0x9eba3deccba3f58885f8574fe0ad5c, 0xad658f5af8a9f8aaecefe0dc5e2ea9, 0x630b320a41ecf8886a904ab50fabcf, 0xab],
        [0x17f83611c8e8f9f2ebd26a1a0139d8, 0x8bbc33b70ddefb63d203444b55fb78, 0x4d73fcc4150832910ff93569700ce0, 0x1d294f0e482675c66be3665a6a2182, 0x22216c933b1049d869a7497aadca4a, 0xd33887ebf8b4a794d89b82cc50c4d8, 0x5a793eb6b2fdee24aac6cc27193c23, 0x23c60dede6903ff286c0d253553266, 0xef88ce4631df04e6b8b8c5b4b51fa2, 0xe13f743d552179a8bcbf718ac7aaba, 0x5de05c5537ce807069c5c32c3a4fbe, 0xb66afa086309a3132ce4a7815ed349, 0xfe87093a69ee62da1c1eed85876cb8, 0x6f787e755d8824f85674b30ebf539e, 0x3a9820ba2e72d8baf150e346244caa, 0x8f97576012ae4534ba4c4930c34369, 0x2e51a0fa1509797d0397ac632d86fd, 0x17e6],
        [0x4bdd3f9151a98c262e69137728c6db, 0x13465b3dc22d52a00c8cfcd7155285, 0x8c4755357273090fe916fb467f0bd5, 0x1f7a5357b20d206328036040fa2fbc, 0x430c4d4328e8a2e80bfb15242a83ca, 0xb2784dfccb6f0d84a508b9a5477744, 0x305ef3471ba75165ff0bce2be0c05a, 0x50ebad5b9eb4780ee089cfe10b31c5, 0xd17888bf0f993b60879cd092757a28, 0x9bf7d727cbfbec815a45a391a33b06, 0x918ce5ae9afbf05d0cbf227b919e1a, 0xabf2f44db983452df80753f66d17d8, 0x67b6472635f6efb6445c1f87269774, 0x835ae20cd2a5a28b942bda41f1c08d, 0x288285d4f2fef6f2962aec2073cfed, 0x798a68139b058cd050cb4acd96997, 0x30b34313b7978b371dfab8f9028548, 0x14],
        [241, 218, 202, 106, 39, 22, 228, 84, 126, 198, 185, 8, 106, 241, 174, 198, 196, 134, 243, 59, 199, 51, 177, 205, 77, 244, 144, 143, 152, 6, 94, 100]
    );
}

#[test]
fn test_verify_rsa_pss_2048_e_65537_salt_64_with_sha_256(){
    verify_rsa_pss::<2048, 18, 32, 64, 65537>(
        [0x4ceae960aa29719fdd9881328d292f, 0xbd7e76b2f1b3f63f09b90c3ccd604c, 0x9e852fe6ddaf671ea29b3f54443402, 0x9b340fed1057e1100bcdb01e5b98cf, 0xb9b4cd59b5d26411a0d26ac2315fd8, 0xa24cc43e27353f1202f050c7245c3c, 0xfe6261ba0c1cc9facc1ce62bb7f109, 0x8c5b7a2ca63a68b3f8b531493cba0, 0x55e51b2089e2ac29b0cc24ff27cc58, 0x20a21e23f9f3d87f87d22f0a206502, 0x547c74aff5bcab4bd170ef899211bb, 0xb47ec7e0474189a85d3ea5380206cd, 0x374be01fa41138f6d68c2d55401c94, 0x5e8fa69fa59c4f8f67584df76af6f2, 0xf2e7338d0e761de5324c102eda6358, 0xc41690efd3818ed83b6573adac9cec, 0x4532a33263ad5a9200c789f8225f78, 0xcd],
        [0xc689720fccc790d169cdf08c73a3da, 0xf1f67c8b9b52c80a85d9c865c2aa7a, 0xa8b4912ddabdad6f2d22e314976e71, 0x6805ffc8dfb4b70bfec75c0657d52a, 0xe0c2de5b68b46ab21c1b3bed0a903e, 0x7e3118112e40a0a045422c54e0651, 0x18e33f980e08685447328bf445c8ff, 0x802d2d07cdd312470e73206c84d828, 0x2392d9d117554331a4abefce743350, 0xf2ed43ee1f4462fef315af396e8fdc, 0x6ed2e58620d3edc11b179eb2569dad, 0x2df7b5a865f5011f902673e668448d, 0xbe88a7fbb9ae78f79331446c5e0eee, 0xa49832f64204bbef349d4fed390657, 0xcc910640b001fcb7b7fcbac0a61b9a, 0x5ce6f5921e5b4674f6f919641ac6e1, 0x44f37eaeb9ac1966740a0019b44b7f, 0x13f4],
        [0xa9e85e9870e980ee45252e1c379af, 0x7709f85d78b7d70d639d070b864488, 0x112478775a0684f27d8c532a64d015, 0x1656131931b70006905bcc959b5373, 0x86f811d67546264a73ed1e0eddf400, 0xbb24d13da6d8d70762a2b62c764bf6, 0x5eb45ae2802f239575b975e514766f, 0xef4b3e5990905a43a421419525debb, 0x56420f9f348bce288bb93d448c1f8c, 0xfa55473c6070aa0d59bffcd619bb5d, 0x7c1ec1296f539042a7f28f6b6b9e7b, 0xbc7ff751c0c196c61eee5eefa670b4, 0xb9a0bf404ad7565927f66d6922a664, 0xc9b6d645211d31abd552e62160bead, 0x839fa7f63a99ed31e38044916aaafd, 0x2f5e3da8df26d48fe80aa5c440594, 0xae198fdb69efa0d6af356074c7a08e, 0x1a],
        [200, 35, 79, 116, 137, 25, 254, 190, 98, 226, 9, 119, 100, 222, 30, 80, 80, 138, 76, 52, 120, 239, 42, 114, 158, 18, 90, 103, 133, 198, 84, 167]
    );
}

#[test]
fn test_verify_rsa_pss_2048_e_65537_salt_48_with_sha_384(){
   verify_rsa_pss::<2048, 18, 48, 48, 65537>(     
        [0x6fc0b00e2e562fd10239f46c736a1b, 0x9fd0b7a78483b5ef22e1d923f43243, 0xbc024a932dd3e5b08ba4a885bf9415, 0x716399ac624c57f2852d2c7a5f6e80, 0x71c997c4e3c50e1f54287a92325c0d, 0x39ba7219ce55afe4d5e3eb7e848de5, 0xd23c71e04c0463e03ad2fb37e5bd64, 0xfaf718b7ea63eb99927fb883bd642f, 0xb2df99db91c9bbd4b8dd517f0a4e46, 0xe87aa3e8e821cd52b2fc02b57117b8, 0x900dbdbaf7d3a3a81826b9cec1c140, 0xe8c0fd0f88cab63f25560b53110250, 0xb37c730cc37b610de26f1a1ac156ab, 0xc84537253a3092e00536582d85c158, 0x8ddbb89e201be08852c35ee9bc4c4, 0x4ffd90c94995442227f4f41a63bf, 0x6b5855b11429c43dbfa9a0c51b1e56, 0x96],
        [0x307b3a8b2961a92f7e01315244cf01, 0x78b041d8ab2ac704b0a893a60b479, 0x60bb96fe871f9a83da18603116357f, 0x9d510ed6eb86ec43d83c8c9addfe7, 0x62058316c88fe7c18f0d818caaa8bb, 0xfd38d870a1180dbb58d77c1feccc0b, 0xb18faa4ccd1b3bf6b101322db7730c, 0x4a3092ddf6caa144f64adde175c898, 0x2c8d4f4ceccc18f401879b80dbe81d, 0x974ebfd29360223f517201b457282a, 0xafde082447ba7741f4ff12e8c5a90, 0x70a3801d44bb08dc8e672c9fed2bb7, 0x94407cc93943994f053ccce0fc222d, 0xebe38fb58191871d92133176710ed5, 0xd9ea55a5cc561ba0d309c6698c52ff, 0xcf8cdddeed8f09b30e7cbde842156b, 0x50290ae2254138a78bcb1d745d58f, 0x1b3b],
        [0xf90e947ef92d60cdf14b1bc2798fc4, 0x9e41fd7a257e73ff860d80788f90a6, 0x8f3007a89c34d88df8bd1e13dec8cc, 0x18aca9ca5bf0d2367b4e15ca61323, 0xd9fe59466798fccf8afc010d3947b4, 0xac7b8afca27286d474353d2050b713, 0xf0d2576beab2ffe906e813183cc25c, 0xc5d739c79e3a61778291d594a9b8a, 0x18d404153131023fc6535fe1c43670, 0x3b7d62ea8c8a5dcd0839303a883b99, 0x1d5f0129fe17e006b83d581ba2ff63, 0x8f92510a13b0e3ec2709d8bf62cf69, 0x90ada88a228b3b850a8e90c99499ff, 0x8fc84500df4896c40a27fe736bf539, 0x8988e6810ec8b7b8b2c59283003314, 0xd491b14ab3e09c08ad4e9ddaae98fd, 0xba8c579cabe15789c0b9f75614e8c7, 0x93],
        [0, 131, 105, 99, 197, 71, 40, 116, 246, 193, 251, 100, 7, 175, 29, 115, 147, 189, 139, 14, 28, 151, 57, 237, 214, 115, 37, 248, 50, 22, 112, 235, 134, 43, 219, 91, 102, 205, 118, 17, 135, 140, 215, 94, 87, 230, 73, 239]
    );
}

#[test]
fn test_verify_rsa_pss_2048_e_65537_salt_64_with_sha_512(){
   verify_rsa_pss::<2048, 18, 64, 64, 65537>(     
        [0xb5432ce915b3f25f65f241e0c82a7b, 0x5dcc3e75ac7cf3ca67406e89da46ff, 0x55ec6a27e9c8dc273d74825f9a27ea, 0x5ebeca2beb65c5fa3dcf8ef766d7fd, 0x583e52c491989191216d1469b3ec6d, 0xb4a226241abe394d304a3c6539b850, 0xd3621129b09bbf98a2eeac9144e515, 0x3cd3fc1254af4303c70674acf23a62, 0x522bc62d35dd3233aee683a025c67d, 0xd847ac76cc214516a8f3dc6ea96193, 0x72fc960537a06e4507b5affcd16d09, 0x49d084b4af231926c095f1ba0ee856, 0x963bf4361f9257bb7389b7c5bd9e88, 0xfec3d3a9b9c9a815c3cf3e40642b73, 0xa0cb4df3363a038ade5bc5f5316de1, 0x42d576b6751c2c030233e920995c0, 0x5fb37bdbd6cfa101513c9591ebee96, 0xda],
        [0x3e4d3229148ecca9004fb482a44e7, 0x89dcea55aae7fb85dbaa9cc404728a, 0x8b51fe67b55a258ddd1e6c809ad226, 0x791abcf0358f214eaf87b13d112566, 0xd1e12f8a433df352b8ea1adbc28961, 0x2172ca048f341cc42924db2bdeb1b8, 0xda9fcb4171bb39f2b6106d7fd29eb, 0xe8356e18eb9de6b054ab06319cd042, 0x6238255e5e69fa170dffbe4bc6a310, 0xc9ec59cf44d5e1fa8a4899d85215a4, 0x6ffb04a55998d296b41059161687a3, 0xbcc0d20a07e4ecd397ecd95433f4c0, 0xbb4307e74caed37c7679043788cdf3, 0x5a327b3a1199e49d23e3e1dd00e615, 0x7861a2906788d280dc926b55649f10, 0x5ead5dcc8938d81c7a88e8cacd002d, 0xbf5af108db23c486029b215e3356fe, 0x12c1],
        [0xe5c0e4d4f08184f80a6e4433a3c58c, 0x71a54fdf1ef85513c72caab976ceed, 0x8fdafb44c256c8a7188dbbd8b0c9f2, 0x5f65f6dc09ab7a511263c12703bcd8, 0x3b89d016a8fd8105e1c267bf86208a, 0xd0357580b15892d542a00b1d526f29, 0x14f2df2e2b4793b75d0d7c03d476da, 0x82372ecfd4afe8f49a6d48f356ead1, 0x618a57a1854f8277877927abe5c9a, 0x1b00de94efb85556698f53f21af5ad, 0x216b57b55fc0142276288aca351c3b, 0x7e3b2aff555d5de50b66c2918e4069, 0x415a926829ccf24bc44892769fe64, 0x60d734686868b53d3c2df61eecb16e, 0xf6b3cc873b7c76502d074a7c62c676, 0xe84cefa1216793f974cbb02117b595, 0x9201d5186512e1976a22c3c2b50851, 0x9f],
        [206, 211, 40, 8, 246, 127, 63, 96, 248, 102, 30, 170, 197, 205, 91, 53, 1, 82, 67, 72, 104, 211, 86, 239, 173, 183, 0, 147, 201, 76, 113, 84, 139, 226, 92, 121, 139, 222, 82, 42, 114, 157, 249, 94, 79, 236, 144, 43, 214, 216, 20, 147, 55, 169, 19, 57, 54, 172, 199, 184, 154, 103, 51, 135]
    );
}