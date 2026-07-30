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
-- KEYS[6] = sess:{userId}        the owner's session index SET (touched only on the live path)
-- ARGV[1] = new session record JSON (the SessionRecord, never a raw token)
-- ARGV[2] = refresh TTL in seconds (always > 0)
-- ARGV[3] = grace TTL in seconds (0 means "no grace pointer": skip it entirely)
-- ARGV[4] = family id of the presented session ('' means "no family": skip family work)
-- ARGV[5] = sha256(old)  the SET member to move out of the family
-- ARGV[6] = sha256(new)  the SET member to move into the family
-- ARGV[7] = the live-session key prefix, namespace included, for the successor probe
-- ARGV[8] = the live-session member prefix for the session index ('rt' / 'prt')
-- ARGV[9] = the grace-pointer member prefix for the session index ('rp' / 'prp')
--
-- The grace pointer stores `{successorHash}:{session JSON}` — the hash of the session the
-- rotation produced, then a colon, then the record (split on the FIRST colon). Recovery is gated on that successor still
-- being live, because the pointer exists for exactly one purpose: to cover the retry where the
-- old token was consumed but the client never received the new one. Once the successor is gone
-- (revoked from the session list, or swept by "log out everywhere") there is nothing left to
-- recover *to*, and honouring the pointer would rebuild a full-lifetime session out of the very
-- record the user just revoked.
--
-- The script never decodes a stored record: every JSON value it touches is handed back to the
-- caller and parsed there, by a real parser rather than Lua's `cjson`. That keeps it byte-for-byte
-- runnable on any EVAL-capable backend, including the in-memory Redis nest-auth drives its
-- end-to-end tier with.
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
        redis.call('SET', KEYS[3], ARGV[6] .. ':' .. ARGV[1], 'EX', ARGV[3])
    end
    -- Plant the consumed-family marker (surviving the whole refresh lifetime, past the shorter
    -- grace window) and move the family membership from the old hash to the new one, so a
    -- post-grace replay is detected as a reuse and the whole lineage stays revocable. A session
    -- with no family ('') skips this bookkeeping.
    if ARGV[4] ~= '' then
        redis.call('SET', KEYS[4], ARGV[4], 'EX', ARGV[2])
        redis.call('SREM', KEYS[5], ARGV[5])
        redis.call('SADD', KEYS[5], ARGV[6])
        redis.call('EXPIRE', KEYS[5], ARGV[2])
    end
    -- Session-index bookkeeping, INSIDE the script rather than after it. Left to the caller,
    -- it opened a window between the consume and the SADD in which "log out everywhere" could
    -- sweep the index: the sweep would not see the session this rotation had just minted, and
    -- that session would survive a revocation the user was told had happened — and go on
    -- rotating, re-stamping a fresh access token under every later epoch. An attacker holding
    -- a stolen token and refreshing in a loop can aim for that window, and the moment they
    -- would aim for it is precisely the password reset trying to evict them. Inside the
    -- script the two serialize: either the sweep sees the new member and revokes it, or the
    -- rotation runs after the sweep and finds no live key to rotate.
    --
    -- The grace pointer is indexed too, or a token rotated away moments before the sweep
    -- could still recover a session for the whole grace window.
    --
    -- KEYS[6] is touched only here, on the live path — which the caller can only reach when
    -- its own pre-read of KEYS[1] succeeded, so the key is always the real owner's index.
    redis.call('SREM', KEYS[6], ARGV[8] .. ':' .. ARGV[5])
    redis.call('SADD', KEYS[6], ARGV[8] .. ':' .. ARGV[6])
    if tonumber(ARGV[3]) > 0 then
        redis.call('SADD', KEYS[6], ARGV[9] .. ':' .. ARGV[5])
    end
    redis.call('EXPIRE', KEYS[6], ARGV[2])
    redis.call('DEL', KEYS[1])
    return old
end
local grace = redis.call('GET', KEYS[3])
if grace then
    -- The window is single-shot: consume the pointer so one captured token cannot mint a fresh
    -- session on every request for the whole window. It exists to cover the one retry where the
    -- old token was consumed but the client never received the new one.
    redis.call('DEL', KEYS[3])
    -- `{successorHash}:{json}`. Recovery only makes sense while the session the rotation
    -- produced is still live: once it has been revoked, the retry this window exists for has
    -- nothing to land on. Falling through reaches the reuse check below, which is the correct
    -- reading of a consumed token presented after its successor died.
    -- Split on the FIRST colon rather than a fixed width: the hash is hex and the record is
    -- JSON, so neither can contain one before the separator, and a fixed width would silently
    -- mis-split any hash that is not exactly sha256-hex.
    local sep = string.find(grace, ':', 1, true)
    if sep then
        local successor = string.sub(grace, 1, sep - 1)
        if redis.call('EXISTS', ARGV[7] .. ':' .. successor) == 1 then
            return 'GRACE:' .. string.sub(grace, sep + 1)
        end
    end
end
-- Post-grace reuse: the consumed-family marker outlives the grace pointer, so its presence here
-- means this token was validly issued and already rotated — a replay of a consumed token.
local family = redis.call('GET', KEYS[4])
if family then
    return 'REUSED:' .. family
end
return false
