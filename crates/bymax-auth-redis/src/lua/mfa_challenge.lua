-- mfa_challenge: the fused TOTP anti-replay mark + temp-token consume (spec section 7.5.6).
-- Makes "mark this TOTP code used" and "consume this challenge temp token" a single atomic
-- step, so a replayed code can never consume a second temp token and a temp token can never
-- be consumed without simultaneously burning its code.
--
-- KEYS[1] = tu:{hmac(userId:code)}   the TOTP anti-replay marker
-- KEYS[2] = mfa:{sha256(jti)}        the MFA temp-token single-use marker
-- ARGV[1] = anti-replay TTL in seconds
--
-- The temp-token deletion is the single-consume gate. Two checks must BOTH hold for success:
--   1. this exact code has not been used before (the `tu:` NX marker is newly created), and
--   2. the temp token is still present (its `mfa:` marker exists to be deleted).
-- A single temp token may be challenged with several still-valid codes (steps s, s+1, ...,
-- each within the +/-window, each a DIFFERENT `tu:` key); without gating on the temp-token
-- deletion, each distinct code would win its own NX and wrongly issue a session. Gating on the
-- DEL result collapses all such concurrent winners down to the one that actually removed the
-- token.
--
-- Returns 1 only when this call both freshly marked the code AND removed the temp token (the
-- sole winner); 0 otherwise (a replayed code, or a still-fresh code that lost the race for an
-- already-consumed temp token — in which case the just-set marker is rolled back so the code
-- is not burned).
local created = redis.call('SET', KEYS[1], '1', 'NX', 'EX', ARGV[1])
if not created then
    -- The code was already used: a replay. Leave both keys untouched.
    return 0
end
if redis.call('DEL', KEYS[2]) == 1 then
    -- Sole winner: this call freshly marked the code and consumed the temp token.
    return 1
end
-- The temp token was already consumed by another winner using a different code. Roll back the
-- marker we just created so this still-unused code is not burned, and report failure.
redis.call('DEL', KEYS[1])
return 0
