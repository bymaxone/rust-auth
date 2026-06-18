//! Criterion micro-benchmarks for the `bymax-auth-crypto` primitives.
//!
//! Run with `cargo bench -p bymax-auth-crypto --all-features`. The memory-hard KDFs
//! use a small sample count (they dominate wall-clock); the cheap primitives use the
//! default sampling.

use std::hint::black_box;

use bymax_auth_crypto::password::{self, PasswordParams};
use bymax_auth_crypto::{mac, token};
use criterion::Criterion;

/// Cheap keyed/unkeyed digests used for Redis key derivation.
fn digests(c: &mut Criterion) {
    let input = b"tenant-42:user@example.com";
    c.bench_function("sha256/26B", |b| b.iter(|| mac::sha256(black_box(input))));
    c.bench_function("hmac_sha256/26B", |b| {
        b.iter(|| mac::hmac_sha256(black_box(b"server-secret-key"), black_box(input)))
    });
}

/// CSPRNG token generation (heap) vs the fixed-size stack array.
fn tokens(c: &mut Criterion) {
    c.bench_function("generate_secure_token/32B", |b| {
        b.iter(|| token::generate_secure_token(black_box(32)))
    });
    c.bench_function("random_array/12B", |b| b.iter(token::random_array::<12>));
}

/// Memory-hard password hashing/verification (the dominant cost on a login path).
fn passwords(c: &mut Criterion) {
    let mut group = c.benchmark_group("password");
    group.sample_size(10);

    let scrypt_params = PasswordParams::default();
    let scrypt_phc = password::hash(b"correct horse", &scrypt_params).unwrap_or_default();
    group.bench_function("scrypt/hash", |b| {
        b.iter(|| password::hash(black_box(b"correct horse"), black_box(&scrypt_params)))
    });
    group.bench_function("scrypt/verify", |b| {
        b.iter(|| password::verify(black_box(b"correct horse"), black_box(&scrypt_phc)))
    });

    #[cfg(feature = "argon2")]
    {
        let argon_params = PasswordParams {
            active: password::PasswordAlgorithm::Argon2id,
            ..PasswordParams::default()
        };
        let argon_phc = password::hash(b"correct horse", &argon_params).unwrap_or_default();
        group.bench_function("argon2id/hash", |b| {
            b.iter(|| password::hash(black_box(b"correct horse"), black_box(&argon_params)))
        });
        group.bench_function("argon2id/verify", |b| {
            b.iter(|| password::verify(black_box(b"correct horse"), black_box(&argon_phc)))
        });
    }
    group.finish();
}

/// MFA primitives: AES-256-GCM secret encryption and TOTP (the `mfa` feature).
#[cfg(feature = "mfa")]
fn mfa(c: &mut Criterion) {
    use bymax_auth_crypto::{aead, totp};

    let key = [7u8; 32];
    let wire = aead::encrypt(b"JBSWY3DPEHPK3PXP", &key).unwrap_or_default();
    c.bench_function("aead/encrypt", |b| {
        b.iter(|| aead::encrypt(black_box(b"JBSWY3DPEHPK3PXP"), black_box(&key)))
    });
    c.bench_function("aead/decrypt", |b| {
        b.iter(|| aead::decrypt(black_box(&wire), black_box(&key)))
    });

    let secret = b"12345678901234567890";
    c.bench_function("totp/generate", |b| {
        b.iter(|| totp::totp(black_box(secret), black_box(1_700_000_000), 30, 6))
    });
    c.bench_function("totp/verify", |b| {
        b.iter(|| totp::verify(black_box(secret), black_box("287082"), black_box(59), 1))
    });
}

// A manual `main` (rather than the `criterion_group!`/`criterion_main!` macros) keeps
// every bench function private, so the crate-wide `missing_docs` lint has nothing to
// fire on (the macros would generate undocumented public items).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    digests(&mut criterion);
    tokens(&mut criterion);
    passwords(&mut criterion);
    #[cfg(feature = "mfa")]
    mfa(&mut criterion);
    criterion.final_summary();
}
