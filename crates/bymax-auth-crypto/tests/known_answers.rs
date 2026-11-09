//! Known-answer vectors for every wire-visible output of `bymax-auth-crypto`.
//!
//! Each vector comes from a source other than this crate's own output, so the file is an oracle
//! for the dependency generation underneath it rather than a record of what the code happens to
//! return. Provenance is stated beside each group:
//!
//! * **standards** — RFC 4226, RFC 6238, RFC 7914, RFC 9106 and the AES-GCM test cases of
//!   McGrew and Viega, whose values are fixed by the specification;
//! * **nest-auth** — strings produced by `@bymax-one/nest-auth`'s own code path (its
//!   `aes-gcm.ts` wire format via `node:crypto`) or read from the shared
//!   `conformance/wire-contract.json`, never copied into this file;
//! * **independent producer** — scrypt PHC strings written by a program that shares no code with
//!   this crate (Python's `hashlib.scrypt`);
//! * **frozen snapshot** — one Argon2id PHC string written by this crate, because no independent
//!   Argon2 producer was available. It pins that a record already stored stays verifiable; it
//!   cannot show that the first write was right, which the RFC 9106 vector does.
//!
//! The public-API groups use only `bymax_auth_crypto` and must pass unchanged across any
//! upgrade of the primitives beneath it. The two `primitive_*` groups call the underlying crates
//! directly to reach the RFC vectors, which need a salt, a secret and associated data the public
//! API does not expose; those are rewritten with the crate they exercise.

use bymax_auth_crypto::mac::{hmac_sha256, sha256};
use serde_json::Value;

/// The shared wire contract, read from the repository rather than restated here.
const CONTRACT: &str = include_str!("../../../conformance/wire-contract.json");

fn contract() -> Value {
    serde_json::from_str(CONTRACT).unwrap_or(Value::Null)
}

fn hex_of(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn bytes_of(text: &str) -> Vec<u8> {
    hex::decode(text).unwrap_or_default()
}

/// FIPS 180-4 / NIST examples for SHA-256.
#[test]
fn sha256_matches_the_nist_examples() {
    assert_eq!(
        hex_of(&sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex_of(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex_of(&sha256(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

/// RFC 4231 test case 1 and case 2 for HMAC-SHA-256.
#[test]
fn hmac_sha256_matches_rfc_4231() {
    assert_eq!(
        hex_of(&hmac_sha256(&[0x0b; 20], b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        hex_of(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

/// The identifier-key derivation both libraries run, against the shared contract.
///
/// The key is the SHA-256 of `{label}:{secret}`; identifiers and OTP records are the HMAC of
/// their message keyed with the HEX TEXT of that digest, not its raw bytes.
#[test]
fn the_identifier_key_derivation_matches_the_shared_contract() {
    let contract = contract();
    let section = &contract["hmacKeyDerivation"];
    let label = section["label"].as_str().unwrap_or_default();
    let vectors = section["vectors"].as_array().cloned().unwrap_or_default();
    assert!(!label.is_empty() && !vectors.is_empty());
    for vector in &vectors {
        let secret = vector["secret"].as_str().unwrap_or_default();
        let key = hex_of(&sha256(format!("{label}:{secret}").as_bytes()));
        assert_eq!(key, vector["derivedKeyHex"].as_str().unwrap_or_default());
        let message = vector["identifierMessage"].as_str().unwrap_or_default();
        let identifier = hex_of(&hmac_sha256(key.as_bytes(), message.as_bytes()));
        assert_eq!(
            identifier,
            vector["identifierHex"].as_str().unwrap_or_default()
        );
        let code = vector["otpCode"].as_str().unwrap_or_default();
        let record = hex_of(&hmac_sha256(
            key.as_bytes(),
            format!("{identifier}:{code}").as_bytes(),
        ));
        assert_eq!(
            record,
            vector["otpRecordCodeHex"].as_str().unwrap_or_default()
        );
    }
}

#[cfg(feature = "mfa")]
mod mfa {
    use super::bytes_of;
    use bymax_auth_crypto::aead::{decrypt, encrypt};
    use bymax_auth_crypto::totp::{encode_secret_base32, hotp, totp};

    /// RFC 4226 Appendix D: counters 0 to 9 for the ASCII secret `12345678901234567890`.
    #[test]
    fn hotp_matches_rfc_4226_appendix_d() {
        let expected = [
            755_224, 287_082, 359_152, 969_429, 338_314, 254_676, 287_922, 162_583, 399_871,
            520_489,
        ];
        for (counter, want) in expected.iter().enumerate() {
            assert_eq!(hotp(b"12345678901234567890", counter as u64, 6), *want);
        }
    }

    /// RFC 6238 Appendix B, HMAC-SHA-1, eight digits, thirty-second step.
    #[test]
    fn totp_matches_rfc_6238_appendix_b() {
        let table = [
            (59_u64, 94_287_082_u32),
            (1_111_111_109, 7_081_804),
            (1_111_111_111, 14_050_471),
            (1_234_567_890, 89_005_924),
            (2_000_000_000, 69_279_037),
            (20_000_000_000, 65_353_130),
        ];
        for (time, want) in table {
            assert_eq!(totp(b"12345678901234567890", time, 30, 8), want, "T={time}");
        }
    }

    /// The Base32 text of a secret is what is encrypted at rest, so its encoding is pinned too.
    #[test]
    fn base32_encodes_the_rfc_4648_examples() {
        assert_eq!(encode_secret_base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(
            encode_secret_base32(b"Hello!\xde\xad\xbe\xef"),
            "JBSWY3DPEHPK3PXP"
        );
    }

    /// McGrew and Viega, AES-GCM test case 14 (256-bit zero key, zero IV, one zero block),
    /// written in the `base64(iv):base64(tag):base64(ciphertext)` wire format.
    #[test]
    fn decrypt_reads_the_gcm_specification_test_case_14() {
        // ciphertext cea7403d4d606b6e074ec5d3baf39d18, tag d0d1c8a799996bf0265b98b5d48ab919
        let wire = "AAAAAAAAAAAAAAAA:0NHIp5mZa/AmW5i11Iq5GQ==:zqdAPU1ga24HTsXTuvOdGA==";
        assert_eq!(decrypt(wire, &[0u8; 32]).unwrap_or_default(), vec![0u8; 16]);
    }

    /// A wire string written by nest-auth's `encrypt` (`src/server/crypto/aes-gcm.ts`, run under
    /// Node 24 with key bytes `00..1f` and IV bytes `a0..ab`) must decrypt here.
    #[test]
    fn decrypt_reads_a_string_nest_auth_wrote() {
        let key: [u8; 32] =
            bytes_of("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .try_into()
                .unwrap_or([0u8; 32]);
        let wire = "oKGio6Slpqeoqaqr:fReLVTyn/2aw4XV5//x7+g==:rFovehz4Ru8nLdeYNCqYjg==";
        assert_eq!(
            String::from_utf8(decrypt(wire, &key).unwrap_or_default()).unwrap_or_default(),
            "JBSWY3DPEHPK3PXP"
        );
        assert!(decrypt(wire, &[0u8; 32]).is_err(), "another key must fail");
    }

    /// What this crate writes has the wire shape nest-auth reads: three base64 segments of 12,
    /// 16 and `len` bytes.
    #[test]
    fn encrypt_writes_the_three_segment_wire_nest_auth_reads() {
        use base64_shape::decoded_lengths;
        let key = [7u8; 32];
        let wire = encrypt(b"JBSWY3DPEHPK3PXP", &key).unwrap_or_default();
        assert_eq!(decoded_lengths(&wire), Some((12, 16, 16)));
        assert_eq!(
            decrypt(&wire, &key).unwrap_or_default(),
            b"JBSWY3DPEHPK3PXP"
        );
    }

    /// Lengths of the decoded segments of a wire string, without a base64 dependency: the
    /// standard alphabet with padding is the only form accepted.
    mod base64_shape {
        fn decoded_len(segment: &str) -> Option<usize> {
            let padding = segment.chars().rev().take_while(|c| *c == '=').count();
            let valid = segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='));
            (valid && segment.len().is_multiple_of(4) && padding <= 2)
                .then(|| segment.len() / 4 * 3 - padding)
        }

        pub fn decoded_lengths(wire: &str) -> Option<(usize, usize, usize)> {
            let mut parts = wire.split(':');
            let (iv, tag, body) = (parts.next()?, parts.next()?, parts.next()?);
            parts.next().is_none().then_some(())?;
            Some((decoded_len(iv)?, decoded_len(tag)?, decoded_len(body)?))
        }
    }
}

#[cfg(feature = "scrypt")]
mod scrypt_vectors {
    use bymax_auth_crypto::password::{PasswordParams, needs_rehash, verify};

    /// Written by Python's `hashlib.scrypt` (OpenSSL), password `vector-pass phrase`, N=2^14,
    /// r=8, p=1, a 32-byte derived key.
    const PHC_32: &str =
        "$scrypt$ln=14,r=8,p=1$AAECAwQFBgcICQoLDA0ODw$ac0LAYVvIxHZdNAIkutmspqPvjD/tJj2DB8YgrT6jG4";
    /// The same, with a 64-byte derived key (the length nest-auth writes).
    const PHC_64: &str = "$scrypt$ln=14,r=8,p=1$EBESExQVFhcYGRobHB0eHw$nSJ306Wxdllp4YMvkDHFfVCZHO5OzYbBzrk+5x/vID0bja7FzrscZTpVP/SxiSZawK9p9OxEdr3IA6brDSly5g";

    #[test]
    fn a_record_written_by_an_independent_scrypt_verifies() {
        for phc in [PHC_32, PHC_64] {
            assert!(verify(b"vector-pass phrase", phc).unwrap_or(false), "{phc}");
            assert!(!verify(b"vector-pass phrasf", phc).unwrap_or(true), "{phc}");
            assert!(!verify(b"", phc).unwrap_or(true), "{phc}");
        }
    }

    /// Both derived-key lengths are current at the default cost floor of the crate's baseline
    /// parameters, so neither is rewritten on login.
    #[test]
    fn neither_derived_key_length_asks_for_a_rewrite_at_the_recorded_cost() {
        let at_cost = PasswordParams {
            scrypt: bymax_auth_crypto::password::ScryptParams {
                cost_factor: 1 << 14,
                block_size: 8,
                parallelization: 1,
            },
            ..PasswordParams::default()
        };
        assert!(!needs_rehash(PHC_32, &at_cost));
        assert!(!needs_rehash(PHC_64, &at_cost));
    }

    /// RFC 7914 §12, the `pleaseletmein` vector, through the `scrypt` crate directly.
    #[test]
    fn primitive_scrypt_matches_rfc_7914() {
        let params = scrypt::Params::new(14, 8, 1, 64);
        assert!(params.is_ok());
        let Ok(params) = params else { return };
        let mut out = [0u8; 64];
        let written = scrypt::scrypt(b"pleaseletmein", b"SodiumChloride", &params, &mut out);
        assert!(written.is_ok());
        assert_eq!(
            hex::encode(out),
            "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"
        );
    }
}

#[cfg(feature = "argon2")]
mod argon2_vectors {
    use bymax_auth_crypto::password::verify;

    /// Written by this crate (`m=19456,t=2,p=1`, password `vector-pass phrase`) and frozen.
    const SNAPSHOT: &str = "$argon2id$v=19$m=19456,t=2,p=1$OMbrgE2KdILLwdOhZAFAXA$dyFOemn/g4A3Ba1Kvsse99OoyabLi83CROz8ETAAy08";

    #[test]
    fn a_frozen_argon2id_record_keeps_verifying() {
        assert!(verify(b"vector-pass phrase", SNAPSHOT).unwrap_or(false));
        assert!(!verify(b"vector-pass phrasf", SNAPSHOT).unwrap_or(true));
    }

    /// RFC 9106 §5.3, the Argon2id test vector: password 32 bytes of 0x01, salt 16 of 0x02,
    /// secret 8 of 0x03, associated data 12 of 0x04, t=3, m=32 KiB, p=4, 32-byte tag.
    #[test]
    fn primitive_argon2id_matches_rfc_9106() {
        use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
        let params = ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(AssociatedData::new(&[4u8; 12]).unwrap_or_default())
            .output_len(32)
            .build();
        assert!(params.is_ok());
        let Ok(params) = params else { return };
        let argon = Argon2::new_with_secret(&[3u8; 8], Algorithm::Argon2id, Version::V0x13, params);
        assert!(argon.is_ok());
        let Ok(argon) = argon else { return };
        let mut tag = [0u8; 32];
        let written = argon.hash_password_into(&[1u8; 32], &[2u8; 16], &mut tag);
        assert!(written.is_ok());
        assert_eq!(
            hex::encode(tag),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }
}
