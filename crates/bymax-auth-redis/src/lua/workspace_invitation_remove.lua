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
--
-- Returns 1 when the index named the record and was deleted, 0 otherwise.
redis.call('DEL', KEYS[2])
redis.call('SREM', KEYS[3], ARGV[1])
if redis.call('GET', KEYS[1]) == ARGV[1] then
    redis.call('DEL', KEYS[1])
    return 1
end
return 0
