use noir_dl::not_passports_zk_circuits::extract_pk_identity_hash;

// Proves possession of the identity key without revealing it
fn main(sk_identity: Field, identity_key: pub Field, msg_hash: pub Field) {
    assert(extract_pk_identity_hash(sk_identity) == identity_key, "identity key mismatch");
    assert(msg_hash != 0, "empty message");
}

#[test]
fn test_key_possession() {
    main(123456789, 0x232e14ed0140854422b2e5816893fdaab05dc649e91c9c9dd2a34daf8ab3ee6b, 1);
}

#[test(should_fail_with = "identity key mismatch")]
fn test_wrong_key() {
    main(123456788, 0x232e14ed0140854422b2e5816893fdaab05dc649e91c9c9dd2a34daf8ab3ee6b, 1);
}

#[test(should_fail_with = "empty message")]
fn test_empty_message() {
    main(123456789, 0x232e14ed0140854422b2e5816893fdaab05dc649e91c9c9dd2a34daf8ab3ee6b, 0);
}
