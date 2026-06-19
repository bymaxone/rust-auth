-- refresh_rotate: atomic refresh-token rotation with a grace window (spec section 12.5.1).
-- Prevents the double-rotation race: two concurrent requests carrying the same refresh
-- token must never both mint a live session.
--
-- KEYS[1] = rt:{sha256(old)}    the live session key for the presented token
-- KEYS[2] = rt:{sha256(new)}    the destination key for the freshly minted token
-- KEYS[3] = rp:{sha256(old)}    the rotation grace pointer for the old token
-- ARGV[1] = new session record JSON (the SessionRecord, never a raw token)
-- ARGV[2] = refresh TTL in seconds (always > 0)
-- ARGV[3] = grace TTL in seconds (0 means "no grace pointer": skip it entirely)
--
-- Returns the consumed old-session JSON on a live rotation; "GRACE:" .. json when the old
-- token was already rotated but is still inside the grace window; or false (nil) when
-- neither the live token nor a grace pointer is present (an invalid refresh).
--
-- Write-before-delete ordering: the new session key (and, when grace_ttl > 0, the grace
-- pointer) are written BEFORE the old key is removed. Redis does not roll back a script's
-- earlier writes if a later command errors, so any failing SET aborts the script while the
-- old token is still intact — the old refresh token is never consumed without the new
-- session being persisted.
local old = redis.call('GET', KEYS[1])
if old then
    redis.call('SET', KEYS[2], ARGV[1], 'EX', ARGV[2])
    -- A zero grace window means no grace recovery: skip the pointer rather than issue an
    -- `EX 0` SET, which Redis rejects.
    if tonumber(ARGV[3]) > 0 then
        redis.call('SET', KEYS[3], ARGV[1], 'EX', ARGV[3])
    end
    redis.call('DEL', KEYS[1])
    return old
end
local grace = redis.call('GET', KEYS[3])
if grace then
    return 'GRACE:' .. grace
end
return false
