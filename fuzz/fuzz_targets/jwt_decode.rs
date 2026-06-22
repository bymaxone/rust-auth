#![no_main]

//! Fuzz the JWT decode trust boundary: arbitrary bytes are interpreted as a compact
//! JWS and fed to the unverified decoder. The invariant is "never panic, fail closed
//! on malformed input" — a decode either returns a value or a typed error, never an
//! abort.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(token) = std::str::from_utf8(data) {
        // The decoder must tolerate any string: it either decodes into the value or
        // returns a typed error. A panic here would be a defect.
        let _ = bymax_auth_jwt::decode_unverified::<serde_json::Value>(token);
    }
});
