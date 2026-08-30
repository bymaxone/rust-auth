-- invalidate_user_sessions: revoke every session for a user in one transaction
-- (spec sections 12.3 / 12.5). Mirrors nest-auth's invalidateUserSessions, which passes the
-- namespace as ARGV so the script can rebuild each member's fully-qualified key.
--
-- Members of the index SET are full key SUFFIXES, byte-identical to what nest-auth writes:
-- `rt:{hash}` / `prt:{hash}` for a live refresh session, and `rp:{oldHash}` / `prp:{oldHash}`
-- for a rotation grace pointer. The member therefore already names its own keyspace, so the
-- script deletes `{namespace}:{member}` directly instead of re-prefixing a bare hash. That is
-- what lets a logout-all sweep the grace pointers too: with bare-hash members the script could
-- not tell an `rt:` hash from an `rp:` one, so a just-rotated refresh token survived
-- revoke-all for its whole grace window — a live credential outliving the logout meant to kill it.
--
-- KEYS[1] = sess:{subjectHash}  the account's session-index SET (already namespaced). The
--                               suffix is `hmac_sha256(hmacKey, userSubject)`, never a user id.
-- ARGV[1] = namespace       e.g. "auth"
-- ARGV[2] = live prefix     "rt" (dashboard) or "prt" (platform)
-- ARGV[3] = detail prefix   "sd" (dashboard) or "psd" (platform)
--
-- Returns the number of members that were removed.
local members = redis.call('SMEMBERS', KEYS[1])
local live = ARGV[2] .. ':'
for _, member in ipairs(members) do
    -- The member is the key suffix: this one DEL covers a live session AND a grace pointer.
    redis.call('DEL', ARGV[1] .. ':' .. member)
    -- A live member additionally owns a per-session detail record keyed by its bare hash.
    if string.sub(member, 1, #live) == live then
        redis.call('DEL', ARGV[1] .. ':' .. ARGV[3] .. ':' .. string.sub(member, #live + 1))
    end
end
redis.call('DEL', KEYS[1])
return #members
