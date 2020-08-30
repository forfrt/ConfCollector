
--[[
Copyright: 2015-2016, qingteng 
File name: sftp_check.lua
Description: sftp 应用检查 
Author: Ruitao Feng
Version: 1.0
Date: 2016.6.28

Input:
{   
    "args":
    {
        "uuid":"",
        "args":[{"name":Type, "value":Value}]
    }
}

Post:
{
    "stream":{
        "args":{
            "uuid":""
        },
        "result":""
    }
}

Output:
{
    "ret_code":0
    "ret_msg":""
}

--]]

local begin_time = os.time()
local common = agent.require "agent.platform.linux.common"
local execute_shell = common.execute_shell
local execute_shell_l=common.execute_shell_l
agent.load "rex_pcre"
local rex = rex_pcre
local DEBUG=1

if debug_on then
    json_str = [[{"args":{"uuid":"1","args":[{"name":"sftp_check","value":"/root"}]}}]]
end
local json_tb = cjson.decode(json_str)

function debugPrint(str)
    if DEBUG then print(str) end
end

function set2Empty(ret, ...)
    for _,v in ipairs(arg) do
        if not ret[v] then
            ret[v]=""
        end
    end
end

function confRead(ret)
    local confFile=io.open(ret.conf)
    local userFlag=false
    local groupFlag=false
    ret.users={}
    ret.groups={}

    if confFile then
        ret.confAccess=lfs.attributes(ret.conf).permissions
        ret.infoStr=ret.infoStr..string.format("--confRead--Configuration file OPEN in %s\n", ret.conf)
        local user, group
        for line in confFile:lines() do
            while true do
                local lineTbl=trimStr(line, "#")
                line=lineTbl[1]
                if string.len(line)~=0 then
                    if setPropertyByMatch(cur, "AllowUser",  line, [[\s+AllowUser\s+(\S+)]])        then break end
                    if setPropertyByMatch(cur, "DenyUser",   line, [[\s+DenyUser\s+(\S+)]])         then break end
                end
                break
            end
        end
    else
        ret.confAccess=""
        ret.infoStr=ret.infoStr..string.format("--confRead--Configuration file NOT OPEN  in %s\n", ret.conf)
    end
end

function getUsersByGID(gid, group, ret)
    passwdFile=io.open([[/etc/passwd]])
    group.users={}
    if passwdFile then
        ret.infoStr=ret.infoStr.."--getGIDByGroup--/etc/passwd OPENED\n"
        for line in passwdFile:lines() do
            lineTbl=trimStr(line, ":")
            if gid==lineTbl[4] then
                table.insert(group.users, lineTbl[1])
            end
        end
        
    else
        ret.infoStr=ret.infoStr.."--getGIDByGroup--/etc/passwd NOT OPENED\n"
    end
end

function getGIDByGroup(groupName, group, ret)
    groupFile=io.open([[/etc/group]])
    group.GID=""
    if groupFile then
        ret.infoStr=ret.infoStr.."--getGIDByGroup--/etc/group OPENED\n"
        for line in groupFile:lines() do
            lineTbl=trimStr(line, ":")
            if groupName==lineTbl[1] then
                group.GID=lineTbl[3]
            end
        end
    else
        ret.infoStr=ret.infoStr.."--getGIDByGroup--/etc/group NOT OPENED\n"
    end
end

-- Launch a exploit using given payload to specified [hostname:port]
--
-- @param payload The payload carries exploit
-- @param key The type of launched exploit
-- @param hostname The target host name
-- @param hostname The target host port
-- @return Whether the exploit succeed or not
function launch(payload, key, hostname, port)
    local hostBound=socket.connect(hostname, port)
    local headers='t3 12.2.1\nAS:255\nHL:19\nMS:10000000\nPU:t3://us-l-breens:7001\n\n'

    hostBound:send(headers)
    
    local firData=hostBound:receive()
    -- print("received data is", firData)

    local payloadFinal=formPayload(payload)
    local sendSta=hostBound:send(payloadFinal)

    if sendSta then return true end
    return false
end

-- launch the socket gently. Attempt to send the data no more than 3 times
--
-- @param payload The payload carries exploit
-- @param key The type of launched exploit
-- @param hostname The target host name
-- @param hostname The target host port
-- @return Whether the exploit succeed or not
function gentLaunch(payload, key, hostname, port)
    local res=nil
    for i=1, 3 do
        -- print(string.format("Launch %d time for %s", i, existsFiles[key]))
        res=launch(payload, key, hostname, port)
        if res then
            return res
        end
    end
end

-- launch all method of CVE-2015-4852-
--
-- @param payload The payload carries exploit
-- @param key The type of launched exploit
-- @return Whether the exploit succeed or not
function launchAll(hostname, port)
    local launch

    for key, payload in pairs(payloads) do
        launchRes=gentLaunch(payload, key, hostname, port)
    end
end

-- Sleep for n seconds
function sleep(n)
  os.execute("sleep " .. tonumber(n))
end

-- search content under given path. The search result is restored in global variable foundFiles
--
-- @param content The string contains content to be searched for
-- @param path The root path to be searched
function searchInFiles(content, path)
    local fileMode
    local f
    local fileReader

    for file in lfs.dir(path) do
        if file~="." and file~=".." then
            fPath=path..'/'..file
            fileMode=lfs.attributes(fPath)
            if type(fileMode)=="table" then
                if fileMode.mode=="file" then
                    fileReader=io.open(fPath, "r")
                    fileContent=fileReader:read("*a")
                    fileReader:close()

                    if string.find(fileContent, content) then
                        table.insert(foundFiles, fPath)
                        -- print(string.format("%s Found in %s", content, fPath))
                    end
                end
                if fileMode.mode=="directory" then
                    searchInFiles(content, fPath)
                end
            end
        end
    end

end
-- The common function to handle runtime code and runtime message
--
-- If [code] equals to 0, [msg] is restored in the index [key1] of table [ret]
-- Otherwise, [msg] is restored in the index [key2] of table [ret]
--
-- @param ret The result table that stores the informations of runtime
-- @param code runtime code
-- @param msg runtime msg
function handleStatus(ret, code, msg, key1, key2)
    if code==0 then
        ret[key1]=msg
    else
        ret[key2]=ret[key2]..msg
    end
end

-- Check if the string [ver] is contained in the table [vulVers]
-- @param ver The string that may be included by talbe [vulVers]
-- @param vulVers The table that may contains the [ver] string
function verContain(ver, vulVers)
    for _, value in pairs(vulVers) do
        if value==ver then
            return 1
        end
    end
    return 0
end


function setPropertyByMatch(ret, pro, str, match)
    local tmpPro=rex.match(str, match)
    if tmpPro then
        if ret[pro] then
            ret[pro]=ret[pro].."|"..tmpPro
        else
            ret[pro]=tmpPro
        end
        return true
    end
    return false
end

-- Check for vulnerabilities exists in current openssl by comparing its version information
-- TODO: use POC to make the result more reliable ( Poc for CVE-2014-0160 almost finished )
function check4Vuls(version)

    local CVE20140160={"1.0.1", "1.0.1a", "1.0.1b", "1.0.1c", "1.0.1d", "1.0.1e", "1.0.1f"}
    local cveDB={}

    cveDB["20140160"]=verContain(version, CVE20140160)

    return cveDB
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

-- Convert an integer into hex string
--
-- e.g. The output of DEC_HEX(26) is '1a'
--
-- @param IN The integer to be converted
-- @return The String contains the hex form of IN
function DEC_HEX(IN)
    local B,K,OUT,I,D=16,"0123456789abcdef","",0
    while IN>0 do
        I=I+1
        IN,D=math.floor(IN/B),math.mod(IN,B)+1
        OUT=string.sub(K,D,D)..OUT
    end
    return OUT
end

-- prepend '0' to the str until the length of str is 8
--
-- @param str The String to be prepended '0' to
-- @return The prepended string. If the length of str is more than 8, nil will be returned
function prependTo8(str)
    if str:len()<=8 then
        local prependNum=8-str:len()
        for i=1, prependNum do
            str='0'..str
        end
    else
        return nil
    end

    return str
end

debugPrint("\n\n\n--script--Begins\n")
local tmp_code, tmp_msg
local msg_str = ""
local host = agent.get_erlang_data_server_host()
if string.sub(host, -1, -1) ~= "/" then
    host = host.."/"
end
local url = host.."api/v1/data_collection"
for _,one_cmd in pairs(json_tb.args.args) do
    local cmd = ""
    if one_cmd.name == "openssl_check" then
        tmp_code, tmp_msg = openssl_check() 
    end
    if tmp_code ~= 0 then
        msg_str = msg_str.." execute "..one_cmd.name.." error: "..tostring(tmp_code).." "..
            tostring(common.trim(tmp_msg), " ")
        local data = {args={uuid=json_tb.args.uuid},result=agent.base64_encode(tmp_msg)}
        if debug_on then
            agent.lua_print_r(data)
        end
        local j_str = cjson.encode(data)
        local is_compress = true
        tmp_code, http_code, tmp_msg = agent.post_json_to_srv(url, j_str, is_compress)
        if tmp_code ~= 0 and http_code ~= 200 then
            msg_str = msg_str.." post json to server error: "..tostring(tmp_code).." "..
                tostring(http_code).." "..tostring(tmp_msg)
        end
    else
        local data = {args={uuid=json_tb.args.uuid},result=agent.base64_encode(tmp_msg)}
        if debug_on then
            agent.lua_print_r(data)
        end
        local j_str = cjson.encode(data)
        local is_compress = true
        tmp_code, http_code, tmp_msg = agent.post_json_to_srv(url, j_str, is_compress)
        if tmp_code ~= 0 and http_code ~= 200 then
            msg_str = msg_str.." post json to server error: "..tostring(tmp_code).." "..
                tostring(http_code).." "..tostring(tmp_msg)
        end
    end
end

local ret = {}
ret.ret_code = tmp_code
ret.ret_msg = msg_str
ret.req_id = json_tb.req_id
ret.begin_time = begin_time
ret.end_time = os.time()
cjson.encode_empty_table_as_object(false)
local json_rt = cjson.encode(ret)
if debug_on then
    agent.lua_print_r(ret)
else
    agent.sendmsg(tostring(json_tb.from), tostring(json_tb.type), "0xFF000000" , json_rt)
end
