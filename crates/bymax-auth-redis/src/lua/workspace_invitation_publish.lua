-- workspace_invitation_publish: publish a workspace invitation in ONE atomic step, with no separate
-- claim. It writes only while the address's index still holds the record key the writer read (an
-- empty ARGV[5] means the writer read none), and, when ARGV[4] is not 0, only while the
-- workspace's pending set holds fewer members than that. It then writes the record, points the
-- index at it, adds the record key to the set, deletes the record it replaces and that record's
-- place in the set, and sets the lifetimes. A writer that read a stale index, or finds the
-- workspace full, writes nothing, so no state exists in which an index names a record that is not
-- yet written, and two overlapping invitations for one address leave exactly one record.
--
-- KEYS[1] = winvidx:{hmac(invitationEmailSubject)}   the address's index (namespaced)
-- KEYS[2] = winv:{sha256(token)}                      the new record (namespaced)
-- KEYS[3] = winvset:{hmac(workspaceSubject)}          the workspace's pending set (namespaced)
-- KEYS[4] = the record the writer read from the index (namespaced); the new record when none
-- ARGV[1] = the new record key as stored in the index and the set, winv:{sha256(token)}
-- ARGV[2] = the record, as JSON
-- ARGV[3] = the lifetime of the record, the index and the set, in seconds
-- ARGV[4] = the most pending invitations the workspace may hold, or 0 for no limit
-- ARGV[5] = the record key the writer read from the index, or '' for none
--
-- Returns 'published', 'lost' when the index no longer holds ARGV[5], or 'full' when the set is at
-- the limit. Only 'published' writes anything.
local current = redis.call('GET', KEYS[1])
if current == false then
    current = ''
end
if current ~= ARGV[5] then
    return 'lost'
end
if tonumber(ARGV[4]) > 0 and redis.call('SCARD', KEYS[3]) >= tonumber(ARGV[4]) then
    return 'full'
end
redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[3])
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[3])
redis.call('SADD', KEYS[3], ARGV[1])
redis.call('EXPIRE', KEYS[3], ARGV[3])
if ARGV[5] ~= '' then
    redis.call('DEL', KEYS[4])
    redis.call('SREM', KEYS[3], ARGV[5])
end
return 'published'
