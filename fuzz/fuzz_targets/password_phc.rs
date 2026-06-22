#![no_main]

//! Fuzz the PHC-string parser (the password-hash trust boundary). A stored hash string
//! is attacker-influenced if a database is compromised; verifying against an arbitrary
//! PHC string must return `Ok(false)` or a typed error, never panic and never an
//! oracle.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(phc) = std::str::from_utf8(data) {
        // A fixed password against an arbitrary PHC string: the parser must fail closed.
        let _ = bymax_auth_crypto::password::verify(b"a-fixed-password", phc);
    }
});
