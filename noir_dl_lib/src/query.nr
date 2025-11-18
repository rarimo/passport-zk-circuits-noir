use std::hash::{self, poseidon::PoseidonHasher};
use crate::smt::smt_verifier;
use crate::not_passports_zk_circuits::{extract_dg1_commitment, extract_pk_identity_hash};


pub fn date_encoder_bytes<let N: u32>(date: [u8; N]) -> (u32, u32, u32) {
    //YYMMDDHHMMSSZ
    // "- 48" is for converting from ASCII to decimal: '0' == 48, '1' == 49, ...
    let yy = (date[0] - 48) as u32 * 10 + (date[1] - 48) as u32;
    let mm = (date[2] - 48) as u32 * 10 + (date[3] - 48) as u32;
    let dd = (date[4] - 48) as u32 * 10 + (date[5] - 48) as u32;

    (yy, mm, dd)
}

pub fn date_decoder(yy: u32, mm: u32, dd: u32) -> Field {
    let TWO_POW_32 = 4294967296;
    let TWO_POW_16 = 65536;

    // We take first decimal digit and shift it by 1 byte (*256), and add 48 * 256 + 48 (convert back to ASCII).
    let d_ecdoded = ((dd / 10) * 256 + dd % 10) + 12336;
    let m_ecdoded = ((mm / 10) * 256 + mm % 10) + 12336;
    let y_ecdoded = ((yy / 10) * 256 + yy % 10) + 12336;

    y_ecdoded as Field * TWO_POW_32 + m_ecdoded as Field * TWO_POW_16 + d_ecdoded as Field
}

// Date is hex for utf-8 encoded YYMMDD
// To compare dates we need current date (20 | 21 centuary)
pub fn date_is_less(date1: Field, date2: Field, current: Field) -> u1{
    let data1_bytes = date1.to_be_bytes::<6>();
    let data2_bytes = date2.to_be_bytes::<6>();
    let datac_bytes = current.to_be_bytes::<6>();

    let mut (yy1, mm1, dd1) = date_encoder_bytes(data1_bytes);
    let mut (yy2, mm2, dd2) = date_encoder_bytes(data2_bytes);
    let mut (yyc, mmc, ddc) = date_encoder_bytes(datac_bytes);

    if (yy1 > yyc){
        yy1 += 1900;
    } else {
        yy1 += 2000;
    }

    if (yy2 > yyc){
        yy2 += 1900;
    } else {
        yy2 += 2000;
    }

    let verdict = (yy1 < yy2) + (yy1 == yy2) * ((mm1 < mm2) + (mm1 == mm2) * (dd1 < dd2)); 

    verdict as u1
}

fn identity_state_verifier(
    sk_identity: Field,
    pk_pass_hash: Field,
    dg_commit: Field,
    identity_counter: Field,
    timestamp: Field,
    root: Field,
    siblings: [Field; 80],
) {
    let sk_iden_hash = extract_pk_identity_hash(sk_identity);

    let mut position_hasher = PoseidonHasher::default();
    position_hasher.write(pk_pass_hash);
    position_hasher.write(sk_iden_hash);

    let tree_position = position_hasher.finish();
    let mut value_hasher = PoseidonHasher::default();

    value_hasher.write(dg_commit);
    value_hasher.write(identity_counter);
    value_hasher.write(timestamp);

    let verified = smt_verifier(root, value_hasher.finish(), tree_position, siblings);
    assert(verified == 1, "SMT Check failed");
}

fn citizenship_check(citizenship: Field, bitmask: Field, is_needed: u1) {
    let country_codes = [
        4276823, //ABW
        4277831, //AFG
        4278095, //AGO
        4278593, //AIA
        4279362, //ALB
        4279876, //AND
        4279892, //ANT
        4280901, //ARE
        4280903, //ARG
        4280909, //ARM
        4281165, //ASM
        4281409, //ATA
        4281415, //ATG
        4281683, //AUS
        4281684, //AUT
        4282949, //AZE
        4342857, //BDI
        4343116, //BEL
        4343118, //BEN
        4343361, //BFA
        4343620, //BGD
        4343634, //BGR
        4343890, //BHR
        4343891, //BHS
        4344136, //BIH
        4344909, //BLM
        4344914, //BLR
        4344922, //BLZ
        4345173, //BMU
        4345676, //BOL
        4346433, //BRA
        4346434, //BRB
        4346446, //BRN
        4346958, //BTN
        4347713, //BWA
        4407622, //CAF
        4407630, //CAN
        4408139, //CCK
        4409413, //CHE
        4409420, //CHL
        4409422, //CHN
        4409686, //CIV
        4410706, //CMR
        4411204, //COD
        4411207, //COG
        4411211, //COK
        4411212, //COL
        4411213, //COM
        4411478, //CPV
        4411977, //CRI
        4412738, //CUB
        4412759, //CUW
        4413522, //CXR
        4413773, //CYM
        4413776, //CYP
        4414021, //CZE
        4474197, //DEU
        4475465, //DJI
        4476225, //DMA
        4476491, //DNK
        4476749, //DOM
        4479553, //DZA
        4539221, //ECU
        4540249, //EGY
        4543049, //ERI
        4543304, //ESH
        4543312, //ESP
        4543316, //EST
        4543560, //ETH
        4606286, //FIN
        4606537, //FJI
        4607051, //FLK
        4608577, //FRA
        4608591, //FRO
        4608845, //FSM
        4669762, //GAB
        4670034, //GBR
        4670799, //GEO
        4671321, //GGY
        4671553, //GHA
        4671810, //GIB
        4671822, //GIN
        4672834, //GMB
        4673090, //GNB
        4673105, //GNQ
        4674115, //GRC
        4674116, //GRD
        4674124, //GRL
        4674637, //GTM
        4674893, //GUM
        4674905, //GUY
        4737863, //HKG
        4738628, //HND
        4739670, //HRV
        4740169, //HTI
        4740430, //HUN
        4801614, //IDN
        4803918, //IMN
        4804164, //IND
        4804436, //IOT
        4805196, //IRL
        4805198, //IRN
        4805201, //IRQ
        4805452, //ISL
        4805458, //ISR
        4805697, //ITA
        4866381, //JAM
        4867417, //JEY
        4869970, //JOR
        4870222, //JPN
        4931930, //KAZ
        4932942, //KEN
        4933466, //KGZ
        4933709, //KHM
        4933970, //KIR
        4935233, //KNA
        4935506, //KOR
        4937556, //KWT
        4997455, //LAO
        4997710, //LBN
        4997714, //LBR
        4997721, //LBY
        4997953, //LCA
        4999493, //LIE
        5000001, //LKA
        5002063, //LSO
        5002325, //LTU
        5002584, //LUX
        5002817, //LVA
        5062979, //MAC
        5062982, //MAF
        5062994, //MAR
        5063503, //MCO
        5063745, //MDA
        5063751, //MDG
        5063766, //MDV
        5064024, //MEX
        5064780, //MHL
        5065540, //MKD
        5065801, //MLI
        5065812, //MLT
        5066066, //MMR
        5066309, //MNE
        5066311, //MNG
        5066320, //MNP
        5066586, //MOZ
        5067348, //MRT
        5067602, //MSR
        5068115, //MUS
        5068617, //MWI
        5069139, //MYS
        5069140, //MYT
        5128525, //NAM
        5129036, //NCL
        5129554, //NER
        5130049, //NGA
        5130563, //NIC
        5130581, //NIU
        5131332, //NLD
        5132114, //NOR
        5132364, //NPL
        5132885, //NRU
        5134924, //NZL
        5197134, //OMN
        5259595, //PAK
        5259598, //PAN
        5260110, //PCN
        5260626, //PER
        5261388, //PHL
        5262423, //PLW
        5262919, //PNG
        5263180, //POL
        5263945, //PRI
        5263947, //PRK
        5263956, //PRT
        5263961, //PRY
        5264197, //PSE
        5265734, //PYF
        5325140, //QAT
        5391701, //REU
        5394261, //ROU
        5395795, //RUS
        5396289, //RWA
        5456213, //SAU
        5456974, //SDN
        5457230, //SEN
        5457744, //SGP
        5457998, //SHN
        5458509, //SJM
        5459010, //SLB
        5459013, //SLE
        5459030, //SLV
        5459282, //SMR
        5459789, //SOM
        5460045, //SPM
        5460546, //SRB
        5460804, //SSD
        5461072, //STP
        5461330, //SUR
        5461579, //SVK
        5461582, //SVN
        5461829, //SWE
        5461850, //SWZ
        5462093, //SXM
        5462339, //SYC
        5462354, //SYR
        5522241, //TCA
        5522244, //TCD
        5523279, //TGO
        5523521, //THA
        5524043, //TJK
        5524300, //TKL
        5524301, //TKM
        5524563, //TLS
        5525326, //TON
        5526607, //TTO
        5526862, //TUN
        5526866, //TUR
        5526870, //TUV
        5527374, //TWN
        5528129, //TZA
        5588801, //UGA
        5589842, //UKR
        5591641, //URY
        5591873, //USA
        5593666, //UZB
        5652820, //VAT
        5653332, //VCT
        5653838, //VEN
        5654338, //VGB
        5654866, //VIR
        5656141, //VNM
        5657940, //VUT
        5721158, //WLF
        5722957, //WSM
        5786456, //XKX
        5850445, //YEM
        5914950, //ZAF
        5918018, //ZMB
        5920581 //ZWE
    ];

    let mut res = 0;
    let bitmask_bits = bitmask.to_le_bits::<240>();

    for i in 0..240 {
        res += (country_codes[i] * (bitmask_bits[i] as Field) == citizenship) as Field;

    }

    assert(res == 1 * is_needed as Field, "Citizenship check failed");
}

// QUERY SELECTOR:
// 0 - nullifier
// 1 - birth date
// 2 - expiration date
// 3 - name
// 4 - nationality
// 5 - citizenship
// 6 - sex
// 7 - document number
// 8 - timestamp lowerbound
// 9 - timestamp upperbound
// 10 - identity counter lowerbound
// 11 - identity counter upperbound
// 12 - passport expiration lowerbound
// 13 - passport expiration upperbound
// 14 - birth date lowerbound
// 15 - birth date upperbound
// 16 - verify citizenship mask as a whitelist
// 17 - verify citizenship mask as a blacklist

// Passport encoding time is UTF-8 "YYMMDD"
// Timestamps has 2 times of encoding:
// - standard (UNIX) timestamp, like 1716482295 (UT - UNIX timestamp)
// - passport timestamp, like UTF-8 "010203" -> 0x303130323033 -> 52987820126259 (PT - passport timestamp)

pub fn query_identity(
    event_id: Field,
    event_data: Field,
    id_state_root: Field,
    selector: Field,
    current_date: Field,
    timestamp_lowerbound: Field,
    timestamp_upperbound: Field,
    identity_count_lowerbound: Field,
    identity_count_upperbound: Field,
    birth_date_lowerbound: Field,
    birth_date_upperbound: Field,
    expiration_date_lowerbound: Field,
    expiration_date_upperbound: Field,
    citizenship_mask: Field,
    sk_identity: Field,
    pk_passport_hash: Field,
    dg1: [u8; 93],
    siblings: [Field; 80],
    timestamp: Field,
    identity_counter: Field,
) -> (
    Field, // nullifier Poseidon3(sk_i, Poseidon1(sk_i), eventID)
    Field, // birthDate: *(PT - passport timestamp)
    Field, // expirationDate: *(PT - passport timestamp)
    Field, // name: surname
    Field, // nameResidual: given name
    Field, // nationality: UTF-8 encoded | "USA" -> 0x555341 -> 5591873
    Field, // citizenship: UTF-8 encoded | "USA" -> 0x555341 -> 5591873
    Field, // Sex: UTF-8 encoded | "F" -> 0x46 -> 70
    Field // document number
) {


    // selector decoding
    let selector_bits = selector.to_be_bits::<18>();

    // ----------------------
    // Passport data decoding
    let mut (birth_date, expiration_date, name, name_residial, nationality, citizenship, sex, doc_number) = dg1_data_extractor(dg1);

    // ----------------------
    // Nullifier calculation
    let mut sk_iden_hasher = PoseidonHasher::default();
    sk_iden_hasher.write(sk_identity);
    let mut nullifier_hasher = PoseidonHasher::default();
    nullifier_hasher.write(sk_identity);
    nullifier_hasher.write(sk_iden_hasher.finish());
    nullifier_hasher.write(event_id);
    let nullifier = nullifier_hasher.finish() * selector_bits[17] as Field;


    // First value is result of comparation, other is selector bit
    // 0 0 -> 1
    // 1 0 -> 1
    // 0 1 -> 0
    // 1 1 -> 1
    // We should pass all situtions except when we fail check but selector bit is 1

    // --------------------------
    // Timestamp lowerbound check
    let mut n1 = (timestamp as u64 >= timestamp_lowerbound as u64) as u8;
    let mut n2 = selector_bits[9] as u8;
    assert((n1 + (1 - n2) - n1 * (1 - n2)) == 1, "Timestamp lowerbound");

    // Timestamp upperbound check

    n1 = (timestamp as u64 <= timestamp_upperbound as u64) as u8;
    n2 = selector_bits[8] as u8;

    assert((n1 + (1 - n2) - n1 * (1 - n2)) == 1, "Timestamp upperbound");

    //---------------------------------
    // Identity counter lowerbound check
    n1 = (identity_counter as u64 >= identity_count_lowerbound as u64) as u8;
    n2 = selector_bits[7] as u8;
    assert((n1 + (1 - n2) - n1 * (1 - n2)) == 1, "Identity counter lowerbound");

    // Identity counter upperbound
    n1 = (identity_counter as u64 <= identity_count_upperbound as u64) as u8;
    n2 = selector_bits[6] as u8;
    assert((n1 + (1 - n2) - n1 * (1 - n2)) == 1, "Identity counter upperbound");

    //---------------------------------
    // Expiration date lowerbound: expirationDateLowerbound < expirationDate
    n1 = (expiration_date as u64 >= expiration_date_lowerbound as u64) as u8;
    n2 = selector_bits[5] as u8;

    assert((n1 + (1 - n2) - n1 * (1 - n2)) == 1, "Expiration date lowerbound");

    // Expiration date upperbound: expirationDate < expirationDateUpperbound
    n1 = (expiration_date as u64 <= expiration_date_upperbound as u64) as u8;
    n2 = selector_bits[4] as u8;
    assert((n1 + (1 - n2) - n1 * (1 - n2)) == 1, "Expiration date upperbound");
    
    //---------------------------------
    // Birth date lowerbound: birthDateLowerbound < birthDate
    n1 = date_is_less(birth_date_lowerbound, birth_date, current_date) as u8;
    n2 = selector_bits[3] as u8;
    assert((n1 + (1 - n2) - n1 * (1 - n2)) == 1, "Birth date lowerbound");

    // Birth date lowerbound: birthDateLowerbound < birthDate
    n1 = date_is_less(birth_date, birth_date_upperbound, current_date) as u8;
    n2 = selector_bits[2] as u8;
    assert((n1 + (1 - n2) - n1 * (1 - n2)) == 1, "Birth date upperbound");

    // dg1 commitment
    let dg1_commit = extract_dg1_commitment(dg1, sk_identity);

    // Verify identity ownerships
    let _ = identity_state_verifier(
        sk_identity,
        pk_passport_hash,
        dg1_commit,
        identity_counter,
        timestamp,
        id_state_root,
        siblings,
    );

    // Citizenship check
    let _ = citizenship_check(
        citizenship,
        citizenship_mask,
        selector_bits[1],
    );


    birth_date *= selector_bits[16] as Field;
    expiration_date *= selector_bits[15] as Field;
    name *= selector_bits[14] as Field;
    name_residial *= selector_bits[14] as Field;
    nationality *= selector_bits[13] as Field;
    citizenship *= selector_bits[12] as Field;
    sex *= selector_bits[11] as Field;
    doc_number *= selector_bits[10] as Field;

    (
        nullifier, birth_date, expiration_date, name, name_residial, nationality, citizenship, sex, doc_number,
    )
}

// QUERY SELECTOR:
// 0 - nullifier   (+)
// 1 - birth date  (+)
// 2 - expiration date (+)
// 3 - name (+)
// 4 - nationality (+)
// 5 - citizenship (+)
// 6 - sex (+)
// 7 - document number (+)
// 8 - timestamp lowerbound (+)
// 9 - timestamp upperbound (+)
// 10 - identity counter lowerbound (+)
// 11 - identity counter upperbound (+)
// 12 - passport expiration lowerbound
// 13 - passport expiration upperbound
// 14 - birth date lowerbound
// 15 - birth date upperbound
// 16 - personal number hash
// 17 - doc type

// Passport encoding time is UTF-8 "YYMMDD"
// Timestamps has 2 times of encoding: 
// - standard (UNIX) timestamp, like 1716482295 (UT - UNIX timestamp)
// - passport timestamp, like UTF-8 "010203" -> 0x303130323033 -> 52987820126259 (PT - passport timestamp)
pub fn query_identity_td1(
    event_id: Field,
    event_data: Field,
    id_state_root: Field,
    selector: Field,
    current_date: Field,
    timestamp_lowerbound: Field,
    timestamp_upperbound: Field,
    identity_count_lowerbound: Field,
    identity_count_upperbound: Field,
    birth_date_lowerbound: Field,
    birth_date_upperbound: Field,
    expiration_date_lowerbound: Field,
    expiration_date_upperbound: Field,
    citizenship_mask: Field,
    sk_identity: Field,
    pk_passport_hash: Field,
    dg1: [u8; 95],
    siblings: [Field; 80],
    timestamp: Field,
    identity_counter: Field,
) -> (
    Field, // nullifier Poseidon3(sk_i, Poseidon1(sk_i), eventID)
    Field, // birthDate: *(PT - passport timestamp)
    Field, // expirationDate: *(PT - passport timestamp)
    Field, // name: surname
    Field, // nationality: UTF-8 encoded | "USA" -> 0x555341 -> 5591873
    Field, // citizenship: UTF-8 encoded | "USA" -> 0x555341 -> 5591873
    Field, // Sex: UTF-8 encoded | "F" -> 0x46 -> 70
    Field, // document number hash
    Field, // personal number hash
    Field, // UTF-8 encoded | "ID"
) {
    // selector decoding
    let selector_bits = selector.to_be_bits::<18>();

    // ----------------------
    // ID card data decoding
    let mut (birth_date, expiration_date, name, nationality, citizenship, sex, doc_number, personal_number, doc_type) = td1_dg1_data_extractor(dg1);

    // ----------------------
    // Document number hasher
    let mut doc_number_hasher = PoseidonHasher::default();
    doc_number_hasher.write(doc_number);
    let mut doc_number_hash = doc_number_hasher.finish();

    // ----------------------
    // Personal number hasher
    let mut pers_number_hasher = PoseidonHasher::default();
    pers_number_hasher.write(personal_number);
    let mut personal_number_hash = pers_number_hasher.finish();

    // ----------------------
    // Nullifier calculation
    let mut sk_iden_hasher = PoseidonHasher::default();
    sk_iden_hasher.write(sk_identity);
    let mut nullifier_hasher = PoseidonHasher::default();
    nullifier_hasher.write(sk_identity);
    nullifier_hasher.write(sk_iden_hasher.finish());
    nullifier_hasher.write(event_id);
    let nullifier = nullifier_hasher.finish() * selector_bits[17] as Field;


    // First value is result of comparation, other is selector bit
    // 0 0 -> 1
    // 1 0 -> 1
    // 0 1 -> 0
    // 1 1 -> 1
    // We should pass all situtions except when we fail check but selector bit is 1

    // --------------------------
    // Timestamp lowerbound check
    let mut n1 = (timestamp as u64 >= timestamp_lowerbound as u64) as u8;
    let mut n2 = selector_bits[9] as u8;
    assert((n1 + (1 - n2) - n1 * (1 - n2)) == 1, "Timestamp lowerbound");

    // Timestamp upperbound check

    n1 = (timestamp as u64 <= timestamp_upperbound as u64) as u8;
    n2 = selector_bits[8] as u8;

    assert((n1 + (1 - n2) - n1 * (1 - n2)) == 1, "Timestamp upperbound");

    //---------------------------------
    // Identity counter lowerbound check
    n1 = (identity_counter as u64 >= identity_count_lowerbound as u64) as u8;
    n2 = selector_bits[7] as u8;
    assert((n1 + (1 - n2) - n1 * (1 - n2)) == 1, "Identity counter lowerbound");

    // Identity counter upperbound
    n1 = (identity_counter as u64 <= identity_count_upperbound as u64) as u8;
    n2 = selector_bits[6] as u8;
    assert((n1 + (1 - n2) - n1 * (1 - n2)) == 1, "Identity counter upperbound");

    //---------------------------------
    // Expiration date lowerbound: expirationDateLowerbound < expirationDate
    n1 = (expiration_date as u64 >= expiration_date_lowerbound as u64) as u8;
    n2 = selector_bits[5] as u8;

    assert((n1 + (1 - n2) - n1 * (1 - n2)) == 1, "Expiration date lowerbound");

    // Expiration date upperbound: expirationDate < expirationDateUpperbound
    n1 = (expiration_date as u64 <= expiration_date_upperbound as u64) as u8;
    n2 = selector_bits[4] as u8;
    assert((n1 + (1 - n2) - n1 * (1 - n2)) == 1, "Expiration date upperbound");
    
    //---------------------------------
    // Birth date lowerbound: birthDateLowerbound < birthDate
    n1 = date_is_less(birth_date_lowerbound, birth_date, current_date) as u8;
    n2 = selector_bits[3] as u8;
    assert((n1 + (1 - n2) - n1 * (1 - n2)) == 1, "Birth date lowerbound");

    // Birth date lowerbound: birthDateLowerbound < birthDate
    n1 = date_is_less(birth_date, birth_date_upperbound, current_date) as u8;
    n2 = selector_bits[2] as u8;
    assert((n1 + (1 - n2) - n1 * (1 - n2)) == 1, "Birth date upperbound");

    // dg1 commitment
    let dg1_commit = extract_dg1_commitment(dg1, sk_identity);

    // Verify identity ownerships
    let _ = identity_state_verifier(
        sk_identity,
        pk_passport_hash,
        dg1_commit,
        identity_counter,
        timestamp,
        id_state_root,
        siblings,
    );

    // Citizenship check
    let _ = citizenship_check(
        citizenship,
        citizenship_mask,
        selector_bits[1],
    );

    birth_date *= selector_bits[16] as Field;
    expiration_date *= selector_bits[15] as Field;
    name *= selector_bits[14] as Field;
    nationality *= selector_bits[13] as Field;
    citizenship *= selector_bits[12] as Field;
    sex *= selector_bits[11] as Field;
    doc_number_hash *= selector_bits[10] as Field;
    personal_number_hash *= selector_bits[1] as Field;
    doc_type *= selector_bits[0] as Field;

    (
        nullifier, birth_date, expiration_date, name, nationality, citizenship, sex, doc_number_hash, personal_number_hash, doc_type
    )
}


// Extract data from dg1
fn dg1_data_extractor
(
    dg1: [u8; 93]
) -> (Field, Field, Field, Field, Field, Field, Field, Field){

    // BIRTH DATE
    let BIRTH_DATE_SIZE  = 6;
    let BIRTH_DATE_SHIFT = 62;

    let mut birth_date = 0;
    let mut current = 1;
    for i in 0..BIRTH_DATE_SIZE{
        birth_date += current * dg1[BIRTH_DATE_SIZE + BIRTH_DATE_SHIFT - 1 - i] as Field;
        current *= 256;
    }   

    // EXPIRATION DATE
    let EXPIRATION_DATE_SIZE  = 6;
    let EXPIRATION_DATE_SHIFT = 70;

    let mut expiration_date = 0;
    current = 1;
    for i in 0..EXPIRATION_DATE_SIZE{
        expiration_date += current * dg1[EXPIRATION_DATE_SIZE + EXPIRATION_DATE_SHIFT - i - 1] as Field;
        current *= 256;
    }
    
    // NAME, 31 bytes
    let NAME_FIELD_SIZE     = 31;
    let NAME_FIELD_SHIFT    = 10;
    let NAME_FIELD_RESIDUAL = 8;

    let mut name = 0;
    let mut name_residial = 0;
    current = 1;
    for i in 0..NAME_FIELD_SIZE{
        name += current * dg1[NAME_FIELD_SIZE + NAME_FIELD_SHIFT - 1 - i] as Field;
        current *= 256;
    }
    current = 1;
    for i in 0..NAME_FIELD_RESIDUAL{
        name_residial += current * dg1[ NAME_FIELD_RESIDUAL + NAME_FIELD_SHIFT + NAME_FIELD_SIZE - 1 - i] as Field;
        current *= 256;
    }

    // NATIONALITY 
    let NATIONALITY_FIELD_SIZE  = 3;
    let NATIONALITY_FIELD_SHIFT = 59;

    let mut nationality = 0;
    current = 1;
    for i in 0..NATIONALITY_FIELD_SIZE{
        nationality += current * dg1[NATIONALITY_FIELD_SIZE + NATIONALITY_FIELD_SHIFT - 1 -  i] as Field;
        current *= 256;
    }

    // CITIZENSHIP CODE (== issuing authority)
    let CITIZENSHIP_FIELD_SIZE  = 3;
    let CITIZENSHIP_FIELD_SHIFT = 7;

    let mut citizenship = 0;
    current = 1;
    for i in 0..CITIZENSHIP_FIELD_SIZE{
        citizenship += current * dg1[CITIZENSHIP_FIELD_SIZE - 1 - i + CITIZENSHIP_FIELD_SHIFT] as Field;
        current *= 256;
    }

    // SEX
    let SEX_POSITION   = 69;
    let mut sex = dg1[SEX_POSITION] as Field;

    // DOCUMENT NUMBER
    let DOCUMENT_NUMBER_SHIFT = 49;
    let DOCUMENT_NUMBER_SIZE  = 9;

    let mut doc_number = 0;
    current = 1;
    for i in 0..DOCUMENT_NUMBER_SIZE{
        doc_number += current * dg1[DOCUMENT_NUMBER_SHIFT + DOCUMENT_NUMBER_SIZE - 1 - i] as Field;
        current *= 256;
    }

    (birth_date, expiration_date, name, name_residial, nationality, citizenship, sex, doc_number)
}

fn td1_dg1_data_extractor
(
    dg1: [u8; 95]
) -> (Field, Field, Field, Field, Field, Field, Field, Field, Field){

    // BIRTH DATE
    let BIRTH_DATE_SIZE  = 6;
    let BIRTH_DATE_SHIFT = 35;

    let mut birth_date = 0;
    let mut current = 1;
    for i in 0..BIRTH_DATE_SIZE{
        birth_date += current * dg1[BIRTH_DATE_SIZE + BIRTH_DATE_SHIFT - 1 - i] as Field;
        current *= 256;
    }   

    // EXPIRATION DATE
    let EXPIRATION_DATE_SIZE  = 6;
    let EXPIRATION_DATE_SHIFT = 43;

    let mut expiration_date = 0;
    current = 1;
    for i in 0..EXPIRATION_DATE_SIZE{
        expiration_date += current * dg1[EXPIRATION_DATE_SIZE + EXPIRATION_DATE_SHIFT - i - 1] as Field;
        current *= 256;
    }
    
    // NAME, 31 bytes
    let NAME_FIELD_SIZE     = 30;
    let NAME_FIELD_SHIFT    = 65;


    let mut name = 0;
    current = 1;
    for i in 0..NAME_FIELD_SIZE{
        name += current * dg1[NAME_FIELD_SIZE + NAME_FIELD_SHIFT - 1 - i] as Field;
        current *= 256;
    }

    // NATIONALITY 
    let NATIONALITY_FIELD_SIZE  = 3;
    let NATIONALITY_FIELD_SHIFT = 50;

    let mut nationality = 0;
    current = 1;
    for i in 0..NATIONALITY_FIELD_SIZE{
        nationality += current * dg1[NATIONALITY_FIELD_SIZE + NATIONALITY_FIELD_SHIFT - 1 -  i] as Field;
        current *= 256;
    }

    // CITIZENSHIP CODE (== issuing authority)
    let CITIZENSHIP_FIELD_SIZE  = 3;
    let CITIZENSHIP_FIELD_SHIFT = 7;

    let mut citizenship = 0;
    current = 1;
    for i in 0..CITIZENSHIP_FIELD_SIZE{
        citizenship += current * dg1[CITIZENSHIP_FIELD_SIZE - 1 - i + CITIZENSHIP_FIELD_SHIFT] as Field;
        current *= 256;
    }

    // SEX
    let SEX_POSITION   = 48;
    let mut sex = dg1[SEX_POSITION] as Field;

    // DOCUMENT NUMBER
    let DOCUMENT_NUMBER_SHIFT = 10;
    let DOCUMENT_NUMBER_SIZE  = 9;

    let mut doc_number = 0;
    current = 1;
    for i in 0..DOCUMENT_NUMBER_SIZE{
        doc_number += current * dg1[DOCUMENT_NUMBER_SHIFT + DOCUMENT_NUMBER_SIZE - 1 - i] as Field;
        current *= 256;
    }

    // PERSONAL NUMBER
    let PERSONAL_NUMBER_SHIFT = 20;
    let PERSONAL_NUMBER_SIZE  = 11;

    let mut personal_number = 0;
    current = 1;
    for i in 0..PERSONAL_NUMBER_SIZE{
        personal_number += current * dg1[PERSONAL_NUMBER_SHIFT + PERSONAL_NUMBER_SIZE - 1 - i] as Field;
        current *= 256;
    }

    // DOCUMENT TYPE
    let DOCUMENT_TYPE_SHIFT = 5;
    let DOCUMENT_TYPE_SIZE  = 2;

    let mut doc_type = 0;
    current = 1;
    for i in 0..DOCUMENT_TYPE_SIZE{
        doc_type += current * dg1[DOCUMENT_TYPE_SHIFT + DOCUMENT_TYPE_SIZE - 1 - i] as Field;
        current *= 256;
    }

    (birth_date, expiration_date, name, nationality, citizenship, sex, doc_number, personal_number, doc_type)
}


