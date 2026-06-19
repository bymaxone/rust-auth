-- brute_force_incr: fixed-window failure counter (spec section 12.5.3). Guarantees the
-- lockout window starts at the FIRST failure and never slides forward, defeating the
-- "one attempt just before expiry" evasion.
--
-- KEYS[1] = lf:{hmac(tenant:email)}
-- ARGV[1] = window TTL in seconds
--
-- Returns the new counter value. The TTL is set only on the 0->1 transition; subsequent
-- failures never extend it.
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
