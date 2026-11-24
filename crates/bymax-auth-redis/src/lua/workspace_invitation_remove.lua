-- workspace_invitation_remove: delete a workspace invitation's record and its place in the pending
-- set, and the address's index only while it still names this record, in one atomic step. A revoke
-- or a resend that lands between an acceptance's write and its spend therefore cannot be undone by
-- the spend: the record's own key and set member always go, and the index goes only if it is still
-- this record's.
--
-- KEYS[1] = winvidx:{hmac(invitationEmailSubject)}   the address's index (namespaced)
-- KEYS[2] = winv:{sha256(token)}                      the record (namespaced)
-- KEYS[3] = winvset:{hmac(workspaceSubject)}          the workspace's pending set (namespaced)
-- ARGV[1] = the record key as stored in the index and the set, winv:{sha256(token)}
-- ARGV[2] = '1' to delete only a record this place owns (its set holds the key, or its index
--           names it), '0' to delete it whatever place it is asked under
--
-- A revoke asks under the place it read the record's key from, so a place and a record key that
-- do not belong together delete nothing. The spend that follows an acceptance asks '0': the
-- record is single-use and must go even when the set or the index no longer names it.
--
-- Returns 1 when the index named the record and was deleted, 0 otherwise.
if ARGV[2] == '1' then
    local owned = redis.call('SISMEMBER', KEYS[3], ARGV[1]) == 1
        or redis.call('GET', KEYS[1]) == ARGV[1]
    if not owned then
        return 0
    end
end
redis.call('DEL', KEYS[2])
redis.call('SREM', KEYS[3], ARGV[1])
if redis.call('GET', KEYS[1]) == ARGV[1] then
    redis.call('DEL', KEYS[1])
    return 1
end
return 0
