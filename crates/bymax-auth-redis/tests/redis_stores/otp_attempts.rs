//! The `attempts` field of a stored OTP record, as the verify script reads it: an absent one
//! counts as zero and a present one that is not a count (zero or a positive integer the script
//! accepts) counts as the ceiling. A child module of the combined store suite, so it reuses that
//! suite's container harness.

use super::*;

const PURPOSE: OtpPurpose = OtpPurpose::EmailVerification;
const CEILING: u32 = 5;

/// Store a fresh record under `id` and return its key.
async fn seed(stores: &RedisStores, id: &str) -> String {
    assert!(stores.put(PURPOSE, id, "123456", 600).await.is_ok());
    format!("auth:otp:email_verification:{id}")
}

#[tokio::test]
async fn a_present_attempts_value_that_is_no_count_refuses_the_right_code_and_consumes() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    let Some(stores) = redis.stores() else { unreachable!() };

    // Negative values and ones `HINCRBY` cannot bump. `tonumber` reads some of them as a number
    // below the ceiling.
    let values = [
        "",
        "x",
        "nan",
        "-nan",
        "-inf",
        "1.5",
        "1e0",
        "0x1",
        " 1",
        "1 ",
        "+1",
        "007",
        "-0",
        "-1",
        "-1000000",
        "-99999999999999999999",
        "9999999999999999999",
    ];
    for (index, value) in values.iter().enumerate() {
        let id = format!("bad-{index}");
        let key = seed(&stores, &id).await;
        assert!(redis.hset_raw(&key, "attempts", value).await);

        let outcome = stores.verify(PURPOSE, &id, "123456", CEILING).await;
        assert!(
            matches!(outcome, Err(AuthError::OtpMaxAttempts)),
            "attempts {value:?} answered {outcome:?}"
        );
        assert_eq!(
            redis.ttl(&key).await,
            -2,
            "attempts {value:?} kept its record"
        );
    }
}

#[tokio::test]
async fn an_absent_or_counting_attempts_value_is_counted_against_the_ceiling() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    let Some(stores) = redis.stores() else { unreachable!() };

    let absent = seed(&stores, "absent").await;
    assert!(redis.hdel_raw(&absent, "attempts").await);
    assert!(stores.verify(PURPOSE, "absent", "123456", 1).await.is_ok());

    for value in ["0", "4"] {
        let id = format!("under-{value}");
        let key = seed(&stores, &id).await;
        assert!(redis.hset_raw(&key, "attempts", value).await);
        assert!(
            stores.verify(PURPOSE, &id, "123456", CEILING).await.is_ok(),
            "attempts {value:?} is under the ceiling"
        );
    }

    for value in ["5", "10", "999999999999999999"] {
        let id = format!("over-{value}");
        let key = seed(&stores, &id).await;
        assert!(redis.hset_raw(&key, "attempts", value).await);
        assert!(
            matches!(
                stores.verify(PURPOSE, &id, "123456", CEILING).await,
                Err(AuthError::OtpMaxAttempts)
            ),
            "attempts {value:?} is at or over the ceiling"
        );
    }
}
