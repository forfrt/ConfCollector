agent.load "rex_pcre"
local rex = rex_pcre
local common = agent.require "agent.platform.linux.common"
local split = common.split

local ONLINE = 1
local OFFLINE = 2
local MANAGER = 3
local OFFICE = 4
local UNKNOWN = 5
local ONLINE_ADD = 6

function classify_ip(ipaddr)
    local a,b = rex.match(ipaddr, [[(\d*)\.(\d*)]])
    a = tonumber(a)
    b = tonumber(b)
    if a == 100 then
        if b == 64 or b == 65 or (b > 75 and b < 80) then
            return MANAGER
        elseif b == 66 or b == 67 then
            return OFFICE
        elseif b > 67 and b < 76 then
            return OFFLINE
        else
            return ONLINE
        end
    elseif a == 192 then
        return OFFLINE
    elseif a == 10 then
        if b == 10 or b == 127 then
            return ONLINE
        else
            return ONLINE
        end
    else
        return UNKNOWN
    end
end

local ip_list = {}
local f = io.open("./agent-info.csv", "rb")
local writer = {}
for i=1,6 do
    writer[i] = io.open("./"..i, "wb")
end

for line in f:lines() do
    local agent_id,internal_ip,external_ip = rex.match(line,[[^([^,]*),([^,]*),([^,]*)]])
    if internal_ip == "0.0.0.0" then
        internal_ip = external_ip
    end
    
    writer[classify_ip(internal_ip)]:write(agent_id.." "..internal_ip.."\n")
end
for i=1,6 do
    writer[i]:close()
end
