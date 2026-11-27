-- otp_verify: attempt-bounded verify + consume (spec section 12.5.4). Makes
-- "check the ceiling, compare the code, bump attempts, consume on success" a single atomic
-- step so concurrent guesses cannot race past the attempt ceiling.
--
-- The plain compare here only decides the attempts bump and the consume; the AUTHORITATIVE
-- constant-time comparison is re-done by the caller (spec section 17).
--
-- The record is a HASH (`code`, `attempts`) rather than a JSON string. `HINCRBY` bumps the
-- counter in place, which is what makes the whole step atomic without decoding anything —
-- and it leaves the key's TTL untouched, so a wrong guess can never extend the OTP lifetime.
-- The previous JSON form needed `cjson`, which is unavailable in the in-memory Redis the
-- nest-auth end-to-end tier runs against, and a decode-in-the-caller design cannot bump
-- atomically at all: N concurrent guesses each read the same counter and each wrote back
-- 1, so the ceiling could be exceeded arbitrarily by submitting in parallel.
--
-- KEYS[1] = otp:{purpose}:{hmac(tenant:email)}
-- ARGV[1] = submitted code
-- ARGV[2] = max attempts
--
-- Returns a two-element array { tag, code }:
--   { "EXPIRED", "" }          no record (TTL elapsed), or a record with no code field
--   { "MAX", "" }              the ceiling was already reached, or the counter cannot be
--                              read (record consumed)
--   { "PRESENT", storedCode }  the record was present and under the ceiling. The record is
--                              consumed on a plain match and its attempts bumped on a plain
--                              mismatch; the caller re-compares constant-time to decide the
--                              returned outcome.
local code = redis.call('HGET', KEYS[1], 'code')
if not code then
    return { 'EXPIRED', '' }
end
-- An absent field counts as 0. A present one counts only as `0` or a positive integer of at most
-- 18 characters, and anything else counts as the ceiling: the counter only ever rises from 0, a
-- negative one buys guesses, and no wrong guess is counted against a value `HINCRBY` cannot bump.
-- `tonumber` alone is not the test: it reads some of those as numbers (a NaN is below every
-- ceiling). The length bound keeps an accepted value within the integers `HINCRBY` holds.
local raw = redis.call('HGET', KEYS[1], 'attempts')
local attempts = 0
if raw then
    if raw == '0' or (#raw <= 18 and string.match(raw, '^[1-9]%d*$')) then
        attempts = tonumber(raw)
    else
        attempts = tonumber(ARGV[2])
    end
end
if attempts >= tonumber(ARGV[2]) then
    redis.call('DEL', KEYS[1])
    return { 'MAX', '' }
end
if code == ARGV[1] then
    redis.call('DEL', KEYS[1])
else
    -- In place, so the residual TTL is preserved: a wrong guess costs an attempt, never extra
    -- lifetime.
    redis.call('HINCRBY', KEYS[1], 'attempts', 1)
end
return { 'PRESENT', code }
