-- refresh_rotate: atomic refresh-token rotation with a grace window and reuse detection
-- (spec sections 12.5.1 / 12.5.2). Prevents the double-rotation race — two concurrent requests
-- carrying the same refresh token must never both mint a live session — and catches the replay
-- of an already-consumed token (a stolen token being reused) once its grace window has closed.
--
-- KEYS[1] = rt:{sha256(old)}     the live session key for the presented token
-- KEYS[2] = rt:{sha256(new)}     the destination key for the freshly minted token
-- KEYS[3] = rp:{sha256(old)}     the rotation grace pointer for the old token
-- KEYS[4] = cf:{sha256(old)}     the consumed-family marker for the old token
-- KEYS[5] = fam:{family}         the family index SET (the presented session's lineage)
-- ARGV[1] = new session record JSON (the SessionRecord, never a raw token)
-- ARGV[2] = refresh TTL in seconds (always > 0)
-- ARGV[3] = grace TTL in seconds (0 means "no grace pointer": skip it entirely)
-- ARGV[4] = family id of the presented session ('' means "legacy, no family": skip family work)
-- ARGV[5] = sha256(old)  the SET member to move out of the family
-- ARGV[6] = sha256(new)  the SET member to move into the family
--
-- Returns the consumed old-session JSON on a live rotation; "GRACE:" .. json when the old token
-- was already rotated but is still inside the grace window; "REUSED:" .. family when the old
-- token was validly issued and already rotated and its grace window has closed (a reuse); or
-- false (nil) when none of those are present (an invalid refresh that was never issued).
--
-- Write-before-delete ordering: the new session key, the grace pointer, and the consumed-family
-- marker are written BEFORE the old key is removed. Redis does not roll back a script's earlier
-- writes if a later command errors, so any failing SET aborts the script while the old token is
-- still intact — the old refresh token is never consumed without the new session being persisted
-- and the consumed marker planted (so a crash can never lose reuse detection).
local old = redis.call('GET', KEYS[1])
if old then
    redis.call('SET', KEYS[2], ARGV[1], 'EX', ARGV[2])
    -- A zero grace window means no grace recovery: skip the pointer rather than issue an
    -- `EX 0` SET, which Redis rejects.
    if tonumber(ARGV[3]) > 0 then
        redis.call('SET', KEYS[3], ARGV[1], 'EX', ARGV[3])
    end
    -- Plant the consumed-family marker (surviving the whole refresh lifetime, past the shorter
    -- grace window) and move the family membership from the old hash to the new one, so a
    -- post-grace replay is detected as a reuse and the whole lineage stays revocable. A legacy
    -- session with no family ('') skips this bookkeeping.
    if ARGV[4] ~= '' then
        redis.call('SET', KEYS[4], ARGV[4], 'EX', ARGV[2])
        redis.call('SREM', KEYS[5], ARGV[5])
        redis.call('SADD', KEYS[5], ARGV[6])
        redis.call('EXPIRE', KEYS[5], ARGV[2])
    end
    redis.call('DEL', KEYS[1])
    return old
end
local grace = redis.call('GET', KEYS[3])
if grace then
    return 'GRACE:' .. grace
end
-- Post-grace reuse: the consumed-family marker outlives the grace pointer, so its presence here
-- means this token was validly issued and already rotated — a replay of a consumed token.
local family = redis.call('GET', KEYS[4])
if family then
    return 'REUSED:' .. family
end
return false
