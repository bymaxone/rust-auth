-- revoke_family: revoke every live session in a refresh-token family in one transaction
-- (spec section 12.5.2). Called on reuse detection to lock out a stolen token's whole lineage:
-- every descendant of the compromised login is deleted, forcing each holder to re-authenticate.
--
-- KEYS[1] = fam:{family}     the family index SET of live session hashes (already namespaced)
-- ARGV[1] = namespace        e.g. "auth"
-- ARGV[2] = refresh prefix   "rt" (dashboard) or "prt" (platform)
-- ARGV[3] = detail prefix    "sd" (dashboard) or "psd" (platform)
-- ARGV[4] = the owner's session-index key (already namespaced), or '' when no member record was
--           readable and there is therefore no index left to prune
--
-- The owner is resolved by the caller rather than decoded here: every member of one family
-- belongs to the same login, so reading one record in the host language keeps this script free
-- of `cjson`. The membership is still re-read here, so a member added between the two steps is
-- revoked too.
--
-- Returns the number of family members that were removed. Idempotent: an unknown or empty
-- family removes nothing.
local members = redis.call('SMEMBERS', KEYS[1])
if #members == 0 then
    redis.call('DEL', KEYS[1])
    return 0
end
local ns, rt, sd, sess_key = ARGV[1], ARGV[2], ARGV[3], ARGV[4]
for _, hash in ipairs(members) do
    redis.call('DEL', ns .. ':' .. rt .. ':' .. hash)
    redis.call('DEL', ns .. ':' .. sd .. ':' .. hash)
    if sess_key ~= '' then
        -- The session index stores full key **suffixes**, not bare hashes, so the member to
        -- prune is `rt:{hash}` (`prt:{hash}` on the platform plane). Removing the bare hash
        -- would leave the revoked session listed forever, until the index itself expired.
        redis.call('SREM', sess_key, rt .. ':' .. hash)
    end
end
redis.call('DEL', KEYS[1])
return #members
