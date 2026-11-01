-- claim_invitation_index: point the invitee index at a new token hash only while it still holds
-- exactly the hash the caller's rank check approved.
--
-- The rank check reads the index and the claim writes it; as two round trips they can disagree
-- about WHICH invitation is being superseded. One script makes the comparison and the write
-- atomic.
--
-- KEYS[1] = invidx:{tenantId}:{invitee_hash}
-- ARGV[1] = the new token hash
-- ARGV[2] = TTL in seconds
-- ARGV[3] = the hash the caller approved, or the empty string for "no entry" (a real hash is
--           always 64 hex characters, so the two cannot be confused)
--
-- Returns 1 when the index was claimed, 0 when it no longer held what the caller approved.
local current = redis.call('GET', KEYS[1])
if (current or '') ~= ARGV[3] then
    return 0
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
return 1
