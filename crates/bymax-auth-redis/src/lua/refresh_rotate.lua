-- refresh_rotate: atomic refresh-token rotation with a grace window (spec section 12.5.1).
-- Prevents the double-rotation race: two concurrent requests carrying the same refresh
-- token must never both mint a live session.
--
-- KEYS[1] = rt:{sha256(old)}    the live session key for the presented token
-- KEYS[2] = rt:{sha256(new)}    the destination key for the freshly minted token
-- KEYS[3] = rp:{sha256(old)}    the rotation grace pointer for the old token
-- ARGV[1] = new session record JSON (the SessionRecord, never a raw token)
-- ARGV[2] = refresh TTL in seconds
-- ARGV[3] = grace TTL in seconds
--
-- Returns the consumed old-session JSON on a live rotation; "GRACE:" .. json when the old
-- token was already rotated but is still inside the grace window; or false (nil) when
-- neither the live token nor a grace pointer is present (an invalid refresh).
local old = redis.call('GET', KEYS[1])
if old then
    redis.call('DEL', KEYS[1])
    redis.call('SET', KEYS[3], ARGV[1], 'EX', ARGV[3])
    redis.call('SET', KEYS[2], ARGV[1], 'EX', ARGV[2])
    return old
end
local grace = redis.call('GET', KEYS[3])
if grace then
    return 'GRACE:' .. grace
end
return false
