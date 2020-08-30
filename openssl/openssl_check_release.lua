--[[
Copyright: 2015-2016, qingteng 
File name: openssl_check.lua
Description: openssl 应用检查 
Author: Ruitao Feng
Version: 1.0
Date: 2016.6.21

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
    json_str = [[{"args":{"uuid":"1","args":[{"name":"openssl_check","value":"/root"}]}}]]
end
local json_tb = cjson.decode(json_str)


-- Get the list of software that using openssl
function getSofList()
    local lsofCmd=[[lsof 2>/dev/null|grep libssl |awk '{print $1}' |sort |uniq]]
    local sofList={}

    local lsofCode, lsofMsg=execute_shell_l(lsofCmd)
    if lsofCode==0 then
        for i, lsofMs in ipairs(lsofMsg) do
            table.insert(sofList, lsofMs)
        end
        return 0, sofList
    else
        return 1, string.format("--getSofList--exec shell fail: %s\n", lsofCmd)
    end

end

-- Check the home directory of openssl used in $PATH
function checkHome()
    local homCmd=[[openssl version -d]]
    local code, msg=execute_shell(homCmd)
    if code then
        return 0, msg
    else
        return 1, string.format("--execMsg--exec shell fail: %s", cmd)
    end
end

-- Check the version of openssl used in $PATH
function checkVer()
    local verCmd=[[openssl version -v]]
    local code, msg=execute_shell(verCmd)
    if code then
        local version=rex.match(msg, [[\d*\.\d*\.\S*]])
        if version then return 0, version else return 0, msg
        end
    else
        return 1, string.format("--execMsg--exec shell fail: %s", cmd)
    end
end

-- http://www.aip.im/2012/04/how-to-check-if-ssl-v2-is-enabled-using-openssl/
-- Check whether localhost supports SSLv2 or not
-- @return runtimeCode, runtimeMsg
function checkSSL2()
    local cmd=string.format([[openssl s_client -connect 127.0.0.1:443 -ssl2]])
    local code, msg=execute_shell(cmd)
    if code==0 or code==1 then
        if rex.match(msg, [[error:1407F0E5]]) or rex.match(msg, [[write:errno=104]]) then
            return 0, string.format("--checkSSL2--The target does NOT SUPPORT SSLv2 protocol\n")

        elseif rex.match(msg, [[unknown\s*option\s*-ssl2]]) then
            return 0, string.format("--checkSSL2--The target does NOT SUPPORT SSLv2 protocol\n")

        elseif rex.match(msg, [[connect:\s*Connection\s*refused]]) then
            return -1, string.format("--checkSSL2--Cannot connect to target address %s\n", cmd)

        elseif rex.match(msg, [[BEGIN\s*CERTIFICATE]]) then
            return -2, string.format("--checkSSL2--The target SUPPORT SSLv2 protocol\n")

        end
        return -3, string.format("--checkSSL2--unexpected result %s\n", msg)
    else
        return 1, string.format("--checkSSL2--Command execution: %s FAILED\n", cmd)
    end
    
end

-- http://security.stackexchange.com/questions/70733/how-do-i-use-openssl-s-client-to-test-for-absence-of-sslv3-support
-- Check whether localhost supports SSLv3 or not
-- @return runtimeCode, runtimeMsg.
function checkSSL3()
    local cmd=[[openssl s_client -connect 127.0.0.1:443 -ssl3]]
    local code, msg=execute_shell(cmd)

    if code==0 or code==1 then
        if rex.match(msg, [[error:14094410]]) and rex.match(msg, [[error:1409E0E5]]) then
            return 0, string.format("--checkSSL3--The target does NOT support SSLv3 protocol\n")

        elseif rex.match(msg, [[unknown\s*option\s*-ssl3]]) then
            return 0, string.format("--checkSSL3--The target does NOT SUPPORT SSLv3 protocol\n")

        -- This means the address can not be found or connection is not able to be set up
        elseif rex.match(msg, [[connect:\s*Connection\s*refused]]) then
            return -1, string.format("--checkSSL3--Cannot connect to target address %s\n", cmd)

        -- This means the connection is set up
        elseif rex.match(msg, [[BEGIN\s*CERTIFICATE]]) then
            return -2, string.format("--checkSSL3--The target SUPPORT SSLv3 protocol\n")

        end
        return -3, string.format("--checkSSL3--unexpected result %s\n", msg)

    else
        return 1, string.format("--checkSSL3--Command execution: %s failed\n", cmd)
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

-- Check for vulnerabilities exists in current openssl by comparing its version information
-- TODO: use POC to make the result more reliable ( Poc for CVE-2014-0160 almost finished )
function check4Vuls(version)

    local CVE20140160={"1.0.1", "1.0.1a", "1.0.1b", "1.0.1c", "1.0.1d", "1.0.1e", "1.0.1f"}
    local cveDB={}

    cveDB["20140160"]=verContain(version, CVE20140160)

    return cveDB
end

function openssl_check()
    local ret={}
    ret.infoStr=""

    local verCode, verMsg=checkVer()
    local homCode, homMsg=checkHome()
    handleStatus(ret, verCode, verMsg, "version", "infoStr")
    handleStatus(ret, homCode, homMsg, "home", "infoStr")
    
    local sofCode, sofMsg=getSofList()
    if sofCode==0 then 
        ret.sofList=sofMsg
    else
        ret.infoStr=sofMsg
    end

    local ssl3Code, ssl3Msg=checkSSL3()
    ret.SSLv3=ssl3Code
    ret.infoStr=ret.infoStr..ssl3Msg
    
    local ssl2Code, ssl2Msg=checkSSL2()
    ret.SSLv2=ssl2Code
    ret.infoStr=ret.infoStr..ssl2Msg

    ret.cveDB=check4Vuls(ret.version)

    return 0, {}
end

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
