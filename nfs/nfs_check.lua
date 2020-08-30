--[[
Copyright: 2015-2016, qingteng 
File name: nfs_check.lua
Description: nfs 应用检查 
Author: Ruitao Feng
Version: 1.0
Date: 2016.6.23

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
local split=common.split
local DEBUG=1

if debug_on then
    json_str = [[{"args":{"uuid":"1","args":[{"name":"nfs_check","value":"/root"}]}}]]
end
local json_tb = cjson.decode(json_str)

function debugPrint(str)
    if DEBUG then print(str) end
end

-- trim the string [str] according to characteristic [del]
-- return A table that contains every part of trimmed string [str]
function trimStr(str, del1, del2)
    local index, index1, index2, sta=nil, nil, nil, 1
    local ret={}
    while true do
        while true do
            index1=string.find(str, del1, sta, -1)

            if del2 then
                index2=string.find(str, del2, sta, -1)
                if index1 then
                    if index2 and index2<index1 then 
                        index=index2 
                    else 
                        index=index1 
                    end
                else
                    index=string.find(str, del2, sta, -1)
                end
            else
                index=index1
            end

            if index then
                if index==sta then sta=index+1 break end
                table.insert(ret, string.sub(str, sta, index-1))
                sta=index+1
            else
                local last=string.sub(str, sta, -1)
                if last~="" then
                    table.insert(ret, last)
                end
                return ret
            end
            break
        end
    end
end

-- Find any value of a given options table [options] in a table of options [tbl]
-- @param detFun The function that takes two strings and return the result whether the second string meets the specification or not
-- @return The found option in given options table
function findOption(tbl, options, detFun)
    for _, value in pairs(tbl) do
        for _, option in pairs(options) do
            if detFun(value, option) then
                return value
            end
        end
    end
    return nil
end

function isEqual(e1, e2)
    return (e1==e2)
end

-- Read the options string in /etc/exports and find the value of each option
-- @param options The option string like rw,all_squash,secure
-- @return A table that contains the value of each option found
function optionsRead(options)
    local optionTbl=trimStr(options, ",")
    local res={}

    local access    ={"ro", "rw"}
    local mapping   ={"all_squash", "no_all_squash", "root_squash", "no_root_squash", "anonuid=\S*", "anongid=\S*"}
    local secure    ={"secure", "insecure"}
    local sync      ={"sync", "async"}
    local wdelay    ={"wdelay", "no_wdelay"}
    local subtree   ={"subtree", "no_subtree"}

    res.access    =findOption(optionTbl, access, isEqual)
    res.mapping   =findOption(optionTbl, mapping, function(e1, e2)
        return rex.match(e1, e2)
    end)
    res.secure    =findOption(optionTbl, secure, isEqual)
    res.sync      =findOption(optionTbl, sync, isEqual)
    res.wdelay    =findOption(optionTbl, wdelay, isEqual)
    res.subtree   =findOption(optionTbl, subtree, isEqual)

    return res
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

function getTomcatAppDir(homeDir)
    local serverConfPath=string.format("%s/%s", homeDir, "conf/server.xml")
    local serverConf=io.open(serverConfPath)
    local appBaseTbl={}
    if serverConf then
        for line in serverConf:lines() do
            local appBase=rex.match(line, [[appBase="([^"]*)"]])
            if appBase then table.insert(appBaseTbl, appBase) end
        end
    else
        return 1, "--getTomcatAppDir--Configuration file not found\n"
    end

    if next(appBaseTbl) == nil then 
        return 1, "--getTomcatAppDir--No appBase found.\n"
    else
        return 0, appBaseTbl
    end 
end

function isTomcatRunning()
    local cmd = [[ps -eo pid,user,uid,group,gid,ucmd,cmd|awk '{if ($6=="java") print $0}']]
    local ps_code, psInfoTable = execute_shell_l(cmd)
    local baseDir
    if ps_code == 0 then
        for i,psInfo in ipairs(psInfoTable) do
            local baseDir=rex.match(psInfo, [[catalina\.base=(\S*)]])
            if baseDir then
                local ret={}
                local dividedInfo = split(psInfo, " ") 
                ret.user=dividedInfo[2]
                ret.baseDir=baseDir
                debugPrint(string.format("--isTomcatRunning--tomcat base home is %s", baseDir))
                return 0, ret
            end
        end
    else
        return -1, "--isTomcatRunning--proc check exec shell fail\n"
    end

    if not baseDir then
        return 1, "--isTomcatRunning--No proc tomcat\n"
    end
    
end

function getTomcatAppDir()

    local ret={}
    local infoStr=""
    local tomcatCode, tomcatMsg=isTomcatRunning()
    if tomcatCode==0 then
        ret.tomcat={}
        ret.tomcat.base=tomcatMsg
        
    end
    
    return 1, "--getTomcatAppDir--Tomcat is not running\n"
    
end

-- Read the configuration context at /etc/exports
function confRead()
    local confFile=io.open("/etc/exports", "r")
    local confs={}
    if confFile then
        for line in confFile:lines() do
            -- dividedInfo=split(line, "")
            dividedInfo=trimStr(line, " ", "\t")
            for k, v in pairs(dividedInfo) do
                print(k, v)
            end
            confs[dividedInfo[1]]={}

            for i=2, #dividedInfo, 1 do
                local address, options=rex.match(dividedInfo[i], [[([^\(]*)\(([^\)]*)\)]])
                debugPrint(string.format("--confRead--dir: %s, address: %s, options: %s\n", dividedInfo[1], address, options))
                local options=optionsRead(options)
                confs[dividedInfo[1]][address]=options
            end
        end
        -- agent.lua_print_r(confs)
        confFile:close()
        return 0, confs
    else
        return 1, "No file /etc/exports found.\n"
    end
end 

-- Check if the nfs process is alive
function procCheck()
    local checkCmd=[[ps -eo pid,user,uid,group,gid,ucmd,cmd|grep nfsd|grep -v grep]]
    local res={}
    
    local procCode, procMsg=execute_shell_l(checkCmd)
    if procCode==0 then
        for _, msg in pairs(procMsg) do
            local proc={}
            local dividedInfo = split(msg, " ") 
            proc.pid = dividedInfo[1]
            proc.user = dividedInfo[2]
            proc.uid = dividedInfo[3]
            proc.group = dividedInfo[4]
            proc.gid = dividedInfo[5]
            proc.ucmd = dividedInfo[6]
            
            proc.cmd=""
            for var=7,#dividedInfo, 1 do
                proc.cmd=proc.cmd..dividedInfo[var].." "
            end
            table.insert(res, cjson.encode(proc))
        end
    else
        return -1, "--procCheck--Proc check exec shell fail.\n" 
    end

    if next(res) == nil then 
        return 1, "--procCheck--No proc nfs.\n"
    else
        return 0, res
    end 
end

function nfs_check()
    local ret={}
    ret.infoStr=""
    local procCode, procMsg=procCheck()
    if procCode==0 then
        ret=procMsg
    else
        ret.infoStr=ret.infoStr..procMsg
    end
    
    local confCode, confMsg=confRead()
    handleStatus(ret, confCode, confMsg, "confs", "infoStr")

    agent.lua_print_r(ret)
    return 0, ret
end

debugPrint("\n\n\n--SCRIPT--Begins\n")
local tmp_code, tmp_msg
local msg_str = ""
local host = agent.get_erlang_data_server_host()
if string.sub(host, -1, -1) ~= "/" then
    host = host.."/"
end
local url = host.."api/v1/data_collection"
for _,one_cmd in pairs(json_tb.args.args) do
    local cmd = ""
    if one_cmd.name == "nfs_check" then
        tmp_code, tmp_msg = nfs_check() 
        tmp_msg=cjson.encode(tmp_msg)
    end
    if tmp_code ~= 0 then
        msg_str = msg_str.." execute "..one_cmd.name.." error: "..tostring(tmp_code).." "..
            tostring(tmp_msg)
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
debugPrint("\n\n\n--SCRIPT--Ends\n")
