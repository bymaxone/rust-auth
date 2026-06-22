#![no_main]

//! Fuzz the Base32 secret decoder (the TOTP-secret trust boundary). Arbitrary input
//! must decode into bytes or return a typed error — never panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(secret) = std::str::from_utf8(data) {
        let _ = bymax_auth_crypto::totp::decode_secret_base32(secret);
    }
});
