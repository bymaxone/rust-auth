-- session_revoke: ownership-checked single revoke (spec section 12.5.2). Closes an
-- IDOR/BOLA hole: a user must not revoke a session hash they do not own. The membership
-- test and the deletes are one atomic unit, so a session cannot be half-revoked.
--
-- KEYS[1] = sess:{userId}     the user's session-index SET
-- KEYS[2] = rt:{sessionHash}  the refresh-session key
-- KEYS[3] = sd:{sessionHash}  the per-session detail key
-- ARGV[1] = rt:{sessionHash}  the SET member to revoke — the full key SUFFIX, not a bare
--                             hash, matching the member format nest-auth writes so either
--                             backend can revoke a session the other created
--
-- Returns 1 when the hash was owned and revoked; 0 when the caller does not own it.
if redis.call('SISMEMBER', KEYS[1], ARGV[1]) == 0 then
    return 0
end
redis.call('SREM', KEYS[1], ARGV[1])
redis.call('DEL', KEYS[2])
redis.call('DEL', KEYS[3])
return 1
