-- invalidate_user_sessions: revoke every session for a user in one transaction
-- (spec sections 12.3 / 12.5). Mirrors nest-auth's invalidateUserSessions, which passes the
-- namespace as ARGV so the script can rebuild each member's fully-qualified key.
--
-- KEYS[1] = sess:{userId}   the user's session-hash SET (already namespaced)
-- ARGV[1] = namespace       e.g. "auth"
-- ARGV[2] = refresh prefix  "rt" (dashboard) or "prt" (platform)
-- ARGV[3] = detail prefix   "sd" (dashboard) or "psd" (platform)
--
-- Returns the number of session members that were removed.
local members = redis.call('SMEMBERS', KEYS[1])
for _, member in ipairs(members) do
    redis.call('DEL', ARGV[1] .. ':' .. ARGV[2] .. ':' .. member)
    redis.call('DEL', ARGV[1] .. ':' .. ARGV[3] .. ':' .. member)
end
redis.call('DEL', KEYS[1])
return #members
