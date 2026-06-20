-- mfa_challenge: the fused TOTP anti-replay mark + temp-token consume (spec section 7.5.6).
-- Makes "mark this TOTP code used" and "consume this challenge temp token" a single atomic
-- step, so a replayed code can never consume a second temp token and a temp token can never
-- be consumed without simultaneously burning its code.
--
-- KEYS[1] = tu:{hmac(userId:code)}   the TOTP anti-replay marker
-- KEYS[2] = mfa:{sha256(jti)}        the MFA temp-token single-use marker
-- ARGV[1] = anti-replay TTL in seconds
--
-- Returns 1 when the marker was newly created (the code had not been seen) and the temp
-- token was therefore consumed; 0 on a replay (the marker already existed and the temp token
-- is left untouched).
local created = redis.call('SET', KEYS[1], '1', 'NX', 'EX', ARGV[1])
if created then
    redis.call('DEL', KEYS[2])
    return 1
end
return 0
