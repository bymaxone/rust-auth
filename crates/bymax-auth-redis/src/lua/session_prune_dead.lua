-- session_prune_dead: remove a session-index member only if the key it names is gone. The
-- existence check and the SREM are one atomic unit: a member whose key is written between a
-- separate EXISTS and a separate SREM would otherwise be dropped while live, and a live
-- session missing from the index survives "sign out everywhere" (the sweep only reaches what
-- the index names).
--
-- KEYS[1] = sess:{subjectHash}  the account's session-index SET
-- KEYS[2] = rt:{sessionHash}    the refresh-session key the member names
-- ARGV[1] = rt:{sessionHash}    the SET member (the full key suffix)
--
-- Returns 1 when the member was dead and removed; 0 when its key exists (nothing changed).
if redis.call('EXISTS', KEYS[2]) == 0 then
    return redis.call('SREM', KEYS[1], ARGV[1])
end
return 0
