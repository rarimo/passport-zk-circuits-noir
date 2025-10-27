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
        16727, 16710, 16719, 16713, 16716, 16708, 16718, 16709, 16722, 16717, 16723, 16721, 16711,
        16725, 16724, 16730, 16969, 16965, 16970, 16966, 16964, 16967, 16968, 16979, 16961, 16972,
        16985, 16986, 16973, 16975, 16978, 16962, 16974, 16980, 16983, 17222, 17217, 17219, 17224,
        17228, 17230, 17225, 17229, 17220, 17223, 17227, 17231, 19277, 17238, 17234, 17237, 17239,
        17240, 19289, 17241, 17242, 17477, 17482, 17485, 17483, 17487, 17498, 17731, 17735, 17746,
        17736, 17747, 17733, 17748, 17993, 17994, 17995, 18002, 17999, 17997, 18241, 18242, 18245,
        18247, 18248, 18249, 18254, 18253, 18263, 18257, 18258, 18244, 18252, 18260, 18261, 18265,
        18507, 18510, 18514, 18516, 18517, 18756, 18765, 18766, 18767, 18757, 18770, 18769, 18771,
        18764, 18772, 19021, 19013, 19023, 19024, 19290, 19269, 19271, 19272, 19273, 19278, 19282,
        19287, 19521, 19522, 19538, 19545, 19523, 19529, 19531, 19539, 19540, 19541, 19791, 19782,
        19777, 19779, 19780, 19783, 19798, 19800, 19784, 19787, 19788, 19796, 19789, 19781, 19790,
        19792, 19802, 19794, 19795, 19797, 19799, 19801, 22868, 20033, 20035, 20037, 20039, 20041,
        20053, 20044, 20047, 20048, 20050, 20058, 20301, 20555, 20545, 20558, 20549, 20552, 20567,
        20551, 20556, 20562, 19280, 20564, 20569, 20563, 20801, 21061, 21071, 21077, 21079, 21313,
        21316, 21326, 21319, 21320, 21322, 21314, 21324, 21334, 21325, 21327, 20557, 21075, 21331,
        21332, 21330, 21323, 21321, 21317, 21338, 21336, 21315, 21337, 21571, 21572, 21575, 21576,
        21578, 21579, 21581, 21580, 21583, 21588, 21582, 21586, 21590, 21591, 21594, 21831, 21825,
        21849, 21843, 21850, 22081, 22083, 22085, 22087, 22089, 22094, 22101, 22342, 22355, 22603,
        22853, 23105, 23117, 23127,
    ];

    let mut res = 0;
    let bitmask_bits = bitmask.to_le_bits::<238>();
    for i in 0..238 {
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
    print(dg1_commit);
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


