//! Tests for the API-key primitives. The grammar and the vector are read from the shared wire
//! contract, never restated, so a change to either side fails here.

use super::*;

/// The `apiKeys` section of the shared wire contract.
fn contract() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/wire-contract.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let root: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
    root["apiKeys"].clone()
}

/// A string field of a contract object.
fn text(value: &serde_json::Value, field: &str) -> String {
    value[field].as_str().unwrap_or_default().to_owned()
}

#[test]
fn the_grammar_constants_are_the_ones_the_contract_pins() {
    let grammar = &contract()["keyGrammar"];
    assert_eq!(text(grammar, "separator"), SEPARATOR.to_string());
    assert_eq!(text(grammar, "defaultPrefix"), DEFAULT_PREFIX);
    assert_eq!(grammar["keyIdLength"], KEY_ID_LEN);
    assert_eq!(grammar["secretLength"], SECRET_LEN);
    // prefix + separator + key id + separator + secret.
    let total = DEFAULT_PREFIX.len() + 1 + KEY_ID_LEN + 1 + SECRET_LEN;
    assert_eq!(grammar["totalLengthWithDefaultPrefix"], total);
}

/// The field names of a contract object, sorted.
fn field_names(value: &serde_json::Value) -> Vec<String> {
    let mut names: Vec<String> = value
        .as_object()
        .map(|object| object.keys().cloned().collect())
        .unwrap_or_default();
    names.sort();
    names
}

#[test]
fn every_grammar_and_vector_field_is_accounted_for_in_both_directions() {
    // Set equality against the loaded sections: a field the contract adds fails here until it is
    // read by a test, and a field it removes fails until the removal is understood.
    let section = contract();
    assert_eq!(
        field_names(&section["keyGrammar"]),
        [
            "defaultPrefix",
            "keyIdLength",
            "parsing",
            "secretLength",
            "separator",
            "totalLengthWithDefaultPrefix"
        ]
    );
    assert_eq!(
        field_names(&section["vector"]),
        ["digest", "key", "keyId", "pepper", "secret"]
    );
}

#[test]
fn the_parsing_rule_is_the_one_the_split_tests_exercise() {
    // `parsing` is prose, so it cannot be read into an assertion. It is pinned verbatim instead:
    // a change to its wording fails here, which is the moment to re-read the parse tests above
    // (the secret may contain the separator; the split is on the first two only).
    assert_eq!(
        text(&contract()["keyGrammar"], "parsing"),
        "split on the FIRST two separators only; the prefix and the keyId contain none, the secret may"
    );
}

#[test]
fn the_contract_vector_formats_parses_and_digests_as_pinned() {
    let vector = &contract()["vector"];
    let (pepper, key_id) = (text(vector, "pepper"), text(vector, "keyId"));
    let (secret, key) = (text(vector, "secret"), text(vector, "key"));
    assert!(!key.is_empty(), "the contract vector was not read");

    assert_eq!(format(DEFAULT_PREFIX, &key_id, &secret), key);
    assert_eq!(
        parse(&key, DEFAULT_PREFIX),
        Some(ParsedApiKey {
            key_id: &key_id,
            secret: &secret
        })
    );
    assert_eq!(digest(&secret, &pepper), text(vector, "digest"));
}

#[test]
fn the_vector_secret_is_the_base64url_of_the_bytes_zero_to_thirty_one() {
    // The contract's secret is a counting pattern, so the encoder is checked against it directly.
    let bytes: Vec<u8> = (0..32).collect();
    assert_eq!(
        encode_base64url(&bytes),
        text(&contract()["vector"], "secret")
    );
}

#[test]
fn base64url_has_no_padding_and_uses_the_url_alphabet() {
    assert_eq!(encode_base64url(&[]), "");
    assert_eq!(encode_base64url(&[0xfb]), "-w");
    assert_eq!(encode_base64url(&[0xfb, 0xff]), "-_8");
    assert_eq!(encode_base64url(&[0xfb, 0xff, 0xbf]), "-_-_");
}

#[test]
fn a_generated_secret_is_43_distinct_base64url_characters() {
    let first = generate_secret();
    assert_eq!(first.len(), SECRET_LEN);
    assert!(is_secret(&first));
    assert_ne!(first, generate_secret());
}

#[test]
fn a_generated_key_survives_a_format_parse_round_trip() {
    let key_id = "0b8f3c1e-5d2a-4c7e-9a14-6f3e8d2b7a90";
    let secret = generate_secret();
    let key = format("svc", key_id, &secret);
    assert_eq!(
        parse(&key, "svc"),
        Some(ParsedApiKey {
            key_id,
            secret: &secret
        })
    );
}

#[test]
fn a_secret_may_contain_the_separator_and_the_split_stays_on_the_first_two() {
    let key_id = DUMMY_KEY_ID;
    let secret = "a_b-c_".to_owned() + &"D".repeat(SECRET_LEN - 6);
    let key = format(DEFAULT_PREFIX, key_id, &secret);
    let parsed = parse(&key, DEFAULT_PREFIX);
    assert_eq!(parsed.map(|p| p.secret), Some(secret.as_str()));
}

#[test]
fn anything_but_exactly_the_grammar_does_not_parse() {
    let id = DUMMY_KEY_ID;
    let sec = DUMMY_SECRET;
    let good = format("bak", id, sec);
    assert!(parse(&good, "bak").is_some());

    let upper_id = id.replace('0', "A");
    let cases: Vec<(String, &str)> = vec![
        (String::new(), "empty"),
        ("bak".to_owned(), "prefix only"),
        ("bak_".to_owned(), "prefix and separator only"),
        (good.replacen("bak_", "xyz_", 1), "wrong prefix"),
        (good.replacen("bak_", "bak-", 1), "wrong separator"),
        (format("bak", &upper_id, sec), "uppercase key id"),
        (format("bak", &id[..35], sec), "short key id"),
        (format("bak", &(id.to_owned() + "0"), sec), "long key id"),
        (format("bak", id, &sec[..42]), "short secret"),
        (format("bak", id, &(sec.to_owned() + "A")), "long secret"),
        (
            format("bak", id, &sec.replace('A', "=")),
            "padding character",
        ),
        (
            format("bak", id, &sec.replace('A', "+")),
            "standard-base64 character",
        ),
        (good.clone() + "\n", "trailing newline"),
        (
            format("bak", id, &("é".to_owned() + &sec[..41])),
            "non-ascii secret",
        ),
        (
            format("bak", "é0000000-0000-4000-8000-000000000000", sec),
            "non-ascii key id",
        ),
        (
            format("bak", &id.replace('-', "_"), sec),
            "key id without its hyphens",
        ),
    ];
    for (raw, why) in cases {
        assert_eq!(parse(&raw, "bak"), None, "{why}: {raw:?}");
    }
}

#[test]
fn the_dummies_are_well_formed_so_every_step_still_runs() {
    assert!(is_key_id(DUMMY_KEY_ID));
    assert!(is_secret(DUMMY_SECRET));
    assert_eq!(DUMMY_DIGEST.len(), DIGEST_HEX_LEN);
    assert!(DUMMY_DIGEST.bytes().all(|b| b == b'0'));
    assert!(
        parse(
            &format(DEFAULT_PREFIX, DUMMY_KEY_ID, DUMMY_SECRET),
            DEFAULT_PREFIX
        )
        .is_some()
    );
}

#[test]
fn a_digest_depends_on_the_pepper_and_the_secret_only() {
    let a = digest("secret-a", "pepper-one");
    assert_eq!(a.len(), DIGEST_HEX_LEN);
    assert_eq!(a, digest("secret-a", "pepper-one"));
    assert_ne!(a, digest("secret-b", "pepper-one"));
    assert_ne!(a, digest("secret-a", "pepper-two"));
}

#[test]
fn digests_match_only_well_formed_equal_values() {
    let d = digest(DUMMY_SECRET, "pepper");
    assert!(digests_match(&d, &d));
    assert!(!digests_match(&d, &digest("other", "pepper")));
    // The lookup-miss comparison: a well-formed zero digest equals itself, which is why the
    // verdict never rests on this comparison alone.
    assert!(digests_match(DUMMY_DIGEST, DUMMY_DIGEST));
    assert!(!digests_match(&d, DUMMY_DIGEST));
}

#[test]
fn a_malformed_stored_digest_never_matches_anything_itself_included() {
    let d = digest(DUMMY_SECRET, "pepper");
    for bad in [
        "",
        "not hex",
        &d.to_uppercase(),
        &d[..63],
        &(d.clone() + "0"),
        &d.replace('a', "g"),
    ] {
        assert!(!digests_match(&d, bad), "{bad:?}");
        assert!(!digests_match(bad, bad), "{bad:?} against itself");
    }
}

#[test]
fn a_digest_decodes_to_the_bytes_its_hex_names() {
    // Every hex digit in both nibble positions: the decode is checked against known bytes, not
    // only against another decode of the same function.
    let (bytes, ok) = decode_digest(&"00112233445566778899aabbccddeeff".repeat(2));
    assert!(ok);
    let expected: Vec<u8> = (0..2u8)
        .flat_map(|_| (0..16u8).map(|i| i * 16 + i))
        .collect();
    assert_eq!(bytes.to_vec(), expected);
}

#[test]
fn digests_that_differ_in_one_nibble_do_not_match() {
    let base = "0".repeat(DIGEST_HEX_LEN);
    for position in [0, 1, DIGEST_HEX_LEN - 2, DIGEST_HEX_LEN - 1] {
        for digit in ['1', '9', 'a', 'f'] {
            let mut other = base.clone();
            other.replace_range(position..=position, &digit.to_string());
            assert!(!digests_match(&base, &other), "{position} {digit}");
        }
    }
    // Two different digits must not decode to the same nibble.
    assert!(!digests_match(
        &"1".repeat(DIGEST_HEX_LEN),
        &"2".repeat(DIGEST_HEX_LEN)
    ));
    assert!(!digests_match(
        &"a".repeat(DIGEST_HEX_LEN),
        &"b".repeat(DIGEST_HEX_LEN)
    ));
}

#[test]
fn base64url_encodes_every_partial_group_length_as_the_alphabet_dictates() {
    // Lengths 0..=4 cover the empty input, a 1-byte and a 2-byte remainder, one whole group and
    // a whole group plus a remainder; the expected strings are RFC 4648 §5 examples.
    assert_eq!(encode_base64url(b"f"), "Zg");
    assert_eq!(encode_base64url(b"fo"), "Zm8");
    assert_eq!(encode_base64url(b"foo"), "Zm9v");
    assert_eq!(encode_base64url(b"foob"), "Zm9vYg");
    assert_eq!(encode_base64url(b"fooba"), "Zm9vYmE");
    assert_eq!(encode_base64url(b"foobar"), "Zm9vYmFy");
}
