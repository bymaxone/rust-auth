-- Release a lock only while it still holds the token the releasing call wrote.
--
-- The per-account MFA transition lock took a fixed value and was released with a bare `DEL`.
-- Its TTL is short and the transition calls into the consumer's repository twice, so a run that
-- overruns has already lost the lock by the time it releases: the delete removes whichever
-- transition holds it now, and a third caller enters beside the second. The serialization the
-- lock exists to provide fails precisely under the load that makes concurrent transitions
-- likely in the first place.
--
-- `GET` then `DEL` from the client cannot express the check — the key can expire and be retaken
-- between the two round trips, which is the interleaving the token is there to catch. One
-- script makes the read and the delete atomic.
--
-- KEYS[1] the lock key
-- ARGV[1] the token the caller wrote when it took the lock
--
-- Returns 1 when this caller's lock was released, 0 when it had already expired or been retaken.
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
