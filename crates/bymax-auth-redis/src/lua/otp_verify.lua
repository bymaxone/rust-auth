
local code = redis.call('HGET', KEYS[1], 'code')
if not code then
    return { 'EXPIRED', '' }
end
local raw = redis.call('HGET', KEYS[1], 'attempts')
local attempts = 0
if raw then
    if raw == '0' or (#raw <= 18 and string.match(raw, '^[1-9]%d*$')) then
        attempts = tonumber(raw)
    else
        attempts = tonumber(ARGV[2])
    end
end
if attempts >= tonumber(ARGV[2]) then
    redis.call('DEL', KEYS[1])
    return { 'MAX', '' }
end
if code == ARGV[1] then
    redis.call('DEL', KEYS[1])
else
    redis.call('HINCRBY', KEYS[1], 'attempts', 1)
end
return { 'PRESENT', code }
