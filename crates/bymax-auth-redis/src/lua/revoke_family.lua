-- revoke_family: revoke every live session in a refresh-token family in one transaction
-- (spec section 12.5.2). Called on reuse detection to lock out a stolen token's whole lineage:
-- every descendant of the compromised login is deleted, forcing each holder to re-authenticate.
--
-- KEYS[1] = fam:{family}     the family index SET of live session hashes (already namespaced)
-- ARGV[1] = namespace        e.g. "auth"
-- ARGV[2] = refresh prefix   "rt" (dashboard) or "prt" (platform)
-- ARGV[3] = detail prefix    "sd" (dashboard) or "psd" (platform)
-- ARGV[4] = session prefix   "sess" (dashboard) or "psess" (platform)
--
-- Returns the number of family members that were removed. Idempotent: an unknown or empty
-- family removes nothing.
local members = redis.call('SMEMBERS', KEYS[1])
if #members == 0 then
    redis.call('DEL', KEYS[1])
    return 0
end
local ns, rt, sd, sess = ARGV[1], ARGV[2], ARGV[3], ARGV[4]
-- Every member of one family belongs to the same user; resolve that user's `sess:` SET from the
-- first member whose record is still readable, so the deleted hashes can be pruned from it too.
local sess_key = nil
for _, hash in ipairs(members) do
    local record = redis.call('GET', ns .. ':' .. rt .. ':' .. hash)
    if record then
        local ok, decoded = pcall(cjson.decode, record)
        if ok and decoded.userId then
            sess_key = ns .. ':' .. sess .. ':' .. decoded.userId
            break
        end
    end
end
for _, hash in ipairs(members) do
    redis.call('DEL', ns .. ':' .. rt .. ':' .. hash)
    redis.call('DEL', ns .. ':' .. sd .. ':' .. hash)
    if sess_key then
        redis.call('SREM', sess_key, hash)
    end
end
redis.call('DEL', KEYS[1])
return #members
