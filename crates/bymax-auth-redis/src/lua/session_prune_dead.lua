-- session_prune_dead: remove session-index members whose own key is gone, and leave every other
-- member in place. The existence check and the SREM are one atomic unit: a member whose key is
-- written between a separate EXISTS and a separate SREM would otherwise be dropped while live,
-- and a live session missing from the index survives "sign out everywhere" (the sweep only
-- reaches what the index names).
--
-- KEYS[1] = sess:{subjectHash}  the account's session-index SET (already namespaced)
-- ARGV[1] = namespace           e.g. "auth"
-- ARGV[2..] = candidate members, each the full key suffix `rt:{hash}` / `prt:{hash}`, so the
--             member names its own key: `{namespace}:{member}`
--
-- Returns the number of members that were dead and removed.
local removed = 0
for i = 2, #ARGV do
    if redis.call('EXISTS', ARGV[1] .. ':' .. ARGV[i]) == 0 then
        removed = removed + redis.call('SREM', KEYS[1], ARGV[i])
    end
end
return removed
