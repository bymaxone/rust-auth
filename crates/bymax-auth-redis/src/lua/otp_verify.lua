-- otp_verify: attempt-bounded verify + consume (spec section 12.5.4). Makes
-- "compare code, bump attempts, consume on success, lock on max" a single atomic step so
-- concurrent guesses cannot race past the attempt ceiling.
--
-- The plain compare here only decides the attempts bump and the consume; the AUTHORITATIVE
-- constant-time comparison is re-done in Rust via `subtle` (spec section 17). The residual
-- TTL is preserved on a wrong guess so an attacker cannot extend the OTP lifetime.
--
-- KEYS[1] = otp:{purpose}:{hmac(tenant:email)}
-- ARGV[1] = submitted code
-- ARGV[2] = max attempts
--
-- Returns a two-element array { tag, code }:
--   { "EXPIRED", "" }          no record (TTL elapsed)
--   { "MAX", "" }              the attempt ceiling was already reached (record consumed)
--   { "PRESENT", storedCode }  the record was present and under the ceiling. The record is
--                              consumed on a plain match and its attempts bumped (residual
--                              TTL preserved) on a plain mismatch; Rust re-compares
--                              constant-time to decide the returned outcome.
local raw = redis.call('GET', KEYS[1])
if not raw then
    return { 'EXPIRED', '' }
end
local record = cjson.decode(raw)
if record.attempts >= tonumber(ARGV[2]) then
    redis.call('DEL', KEYS[1])
    return { 'MAX', '' }
end
if record.code == ARGV[1] then
    redis.call('DEL', KEYS[1])
else
    record.attempts = record.attempts + 1
    local pttl = redis.call('PTTL', KEYS[1])
    if pttl > 0 then
        -- Re-store with the bumped counter under the SAME residual TTL, so a wrong guess can
        -- never extend the OTP lifetime.
        redis.call('SET', KEYS[1], cjson.encode(record), 'PX', pttl)
    else
        -- The record exists but reports no positive residual TTL (it is at/past expiry).
        -- Fail closed by consuming it rather than re-storing a key without a TTL, which would
        -- breach the "every key carries a TTL" invariant.
        redis.call('DEL', KEYS[1])
    end
end
return { 'PRESENT', record.code }
