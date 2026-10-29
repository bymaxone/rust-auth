-- Write the session a grace recovery produced — but only if the account still has one.
--
-- `refresh_rotate.lua` moved the session-index bookkeeping inside itself precisely to close the
-- window in which "log out everywhere" could miss a session a rotation had just minted. The
-- GRACE arm was left outside it: the script returned the recovered record and the engine then
-- wrote the `rt:`, `sess:`, `sd:` and `fam:` keys several awaits later. A `revoke_all` landing
-- in between — from a password reset, an MFA enable, or a ban compensation — swept an index
-- that did not yet contain the session, and the session survived a revocation the user was told
-- had happened. Its access token is signed after the write, so it carries the *post-bump* epoch
-- and verifies. An attacker holding a stolen token gets one grace-eligible token per rotation,
-- so they can keep a continuous stream of these in flight for exactly as long as the victim's
-- reset takes.
--
-- The witness is the per-user session index. `invalidate_user_sessions.lua` deletes the set once
-- it has removed every member, so its absence is precisely "a revoke-all has run"; the successor
-- the grace pointer named is itself indexed, so a legitimate recovery always finds the set
-- present. Checking it and writing in one script makes the two serialize: either the sweep runs
-- first and the recovery is refused, or the recovery runs first and the sweep sees the session.
--
-- The family index is re-checked here for the same reason — the engine's own `EXISTS` ran before
-- the write, so a `revoke_family` in between would have been undone by the `SADD` that follows.
--
-- KEYS[1] rt:{new_hash}        the recovered session record
-- KEYS[2] sess:{subject_hash}  the per-account index, and the witness
-- KEYS[3] sd:{new_hash}        the display-metadata record
-- KEYS[4] fam:{family_id}      the lineage index ('' family: unused)
-- ARGV[1] session record JSON
-- ARGV[2] detail record JSON
-- ARGV[3] ttl seconds
-- ARGV[4] family id ('' for a record that belongs to no lineage)
-- ARGV[5] live index member ('rt:{new_hash}' / 'prt:{new_hash}')
-- ARGV[6] new hash
--
-- Returns 1 when the session was written, 0 when the account had already been swept.
if redis.call('EXISTS', KEYS[2]) == 0 then
  return 0
end
if ARGV[4] ~= '' and redis.call('EXISTS', KEYS[4]) == 0 then
  return 0
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[3])
redis.call('SADD', KEYS[2], ARGV[5])
redis.call('EXPIRE', KEYS[2], ARGV[3])
redis.call('SET', KEYS[3], ARGV[2], 'EX', ARGV[3])
if ARGV[4] ~= '' then
  redis.call('SADD', KEYS[4], ARGV[6])
  redis.call('EXPIRE', KEYS[4], ARGV[3])
end
return 1
