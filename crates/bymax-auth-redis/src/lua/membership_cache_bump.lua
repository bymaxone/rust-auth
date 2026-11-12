-- membership_cache_bump: advance one workspace or membership version counter and set its expiry to
-- the retention, in one step and on every bump, so a counter always carries its retention.
--
-- KEYS[1] = wsv:{hmac(workspaceSubject)} or wmv:{hmac(membershipSubject)}
-- ARGV[1] = the retention in seconds
--
-- Returns the new counter value.
local version = redis.call('INCR', KEYS[1])
redis.call('EXPIRE', KEYS[1], ARGV[1])
return version
