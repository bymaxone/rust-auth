-- membership_cache_fill: write a cached workspace membership only while both version counters still
-- hold the versions the reader saw, and extend every counter that exists to the retention, in one
-- step.
--
-- A counter value must never be reused while an entry bearing it can live: a counter that expires
-- restarts at 1 on its next bump, which would make an entry written under the old value current
-- again. Extending the retention covers a counter that is alive; the comparison covers one that
-- expired between the read and this write, which reads as '0' here and no longer matches. A counter
-- that does not exist is left absent, since a read never creates one.
--
-- KEYS[1] = wsv:{hmac(workspaceSubject)}
-- KEYS[2] = wmv:{hmac(membershipSubject)}
-- KEYS[3] = wm:{hmac(membershipSubject)}:{ARGV[4]}:{ARGV[5]}
-- ARGV[1] = the entry, {"role":"<role>","status":"active"}
-- ARGV[2] = the entry lifetime in seconds (at least 1)
-- ARGV[3] = the counters' retention in seconds
-- ARGV[4] = the workspace version the reader saw
-- ARGV[5] = the membership version the reader saw
--
-- Returns 'written', or 'moved' when a counter no longer holds its version and nothing was written.
local workspaceVersion = redis.call('GET', KEYS[1]) or '0'
local membershipVersion = redis.call('GET', KEYS[2]) or '0'
if workspaceVersion ~= ARGV[4] or membershipVersion ~= ARGV[5] then
    return 'moved'
end
if redis.call('EXISTS', KEYS[1]) == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[3])
end
if redis.call('EXISTS', KEYS[2]) == 1 then
    redis.call('EXPIRE', KEYS[2], ARGV[3])
end
redis.call('SET', KEYS[3], ARGV[1], 'EX', ARGV[2])
return 'written'
