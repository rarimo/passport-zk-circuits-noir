use noir_dl::query::{query_identity_td1};

fn main(
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
) -> pub (Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field){
    let tmp = query_identity_td1(
        event_id,
        event_data,
        id_state_root,
        selector,
        current_date,
        timestamp_lowerbound,
        timestamp_upperbound,
        identity_count_lowerbound,
        identity_count_upperbound,
        birth_date_lowerbound,
        birth_date_upperbound,
        expiration_date_lowerbound,
        expiration_date_upperbound,
        citizenship_mask,
        sk_identity,
        pk_passport_hash,
        dg1,
        siblings,
        timestamp,
        identity_counter,
    );

    (tmp.0, tmp.1, tmp.2, tmp.3, tmp.4, tmp.5, tmp.6, tmp.7, tmp.8, tmp.9, event_id, event_data, id_state_root, selector, current_date, timestamp_lowerbound, timestamp_upperbound, identity_count_lowerbound, identity_count_upperbound, birth_date_lowerbound, birth_date_upperbound, expiration_date_lowerbound, expiration_date_upperbound, citizenship_mask)
}
