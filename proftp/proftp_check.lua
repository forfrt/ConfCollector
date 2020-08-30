--[[
Copyright: 2015-2016, qingteng 
File name: proftp_check.lua
Description: proftp 应用检查 
Author: Ruitao Feng
Version: 1.0
Date: 2016.07.04

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
local split=common.split
local rex = rex_pcre
local DEBUG=1

if debug_on then
    json_str = [[{"args":{"uuid":"1","args":[{"name":"proftp_check","value":"/root"}]}}]]
end
local json_tb = cjson.decode(json_str)

function debugPrint(str)
    if DEBUG then print(str) end
end

function proc_check()
    local cmd = [[ps -eo pid,user,uid,group,gid,ucmd,cmd|awk '{if ($6=="proftpd") print $0}']]
    local ret = {} 
    local tmp_code, proc_info_table = execute_shell_l(cmd)
    if tmp_code == 0 then
        ret.infoStr=string.format("--proc_check--exec shell succeed: %s.\n", cmd)
        for i,line in ipairs(proc_info_table) do
            local cmdPath=""
            local dividedInfo = split(line, " ") 
            for i=7,#dividedInfo-1, 1 do
                cmdPath=cmdPath..dividedInfo[i].." "
            end
            cmdPath=cmdPath..dividedInfo[#dividedInfo]

            ret.ps      = line
            -- ret.cmd     = cmdPath

            ret.pid     = dividedInfo[1]
            ret.user    = dividedInfo[2]
            ret.uid     = dividedInfo[3]
            ret.group   = dividedInfo[4]
            ret.gid     = dividedInfo[5]
            ret.ucmd    = dividedInfo[6]
        end
    else
        ret.infoStr=string.format("--proc_check--exec shell fail: %d, %s, %s.\n", tmp_code, table.concat(pro_info_table), cmd)
        return -1, ret
    end

    if ret.pid == nil then 
        ret.infoStr=string.format("--proc_check--No proc proftpd in running command: %s.\n", cmd)
        return 1, ret
    else
        return 0, ret
    end 
end

function setDefaultConf(ret)
    if ret.conf=="" or not ret.conf then
        ret.conf="/etc/proftpd.conf"
        ret.infoStr=ret.infoStr.."--setDefaultConf--Configuration file location is set to DEFAULT location\n"
    end
end

function splitStr(str, del)
    local index, sta=1, 1
    local ret={}
    while true do
        index=string.find(str, del, sta, -1)
        if index~=nil then
            table.insert(ret, string.sub(str, sta, index-1))
            sta=index+1
        else
            table.insert(ret, string.sub(str, sta, -1))
            break
        end
    end
    return ret
end

function setPropertyByMatch(ret, pro, str, match, table)
    local tmpPro=rex.match(str, match)
    if tmpPro then
        if table then
            if not ret[pro] then
                ret[pro]={}
            end
            ret[pro][tmpPro]={}
            return ret[pro][tmpPro]
        else
            if ret[pro] then
                ret[pro]=ret[pro].."|"..tmpPro
            else
                ret[pro]=tmpPro
                return ret[pro]
            end
        end
    end
    return nil
end

-- http://renlifeng.blog.51cto.com/2076113/637903
-- http://www.wanglifeng.info/sysadmin/openssh-sftp-setting.html
-- http://www.mrliangqi.com/514.html
function confRead(ret)
    setDefaultConf(ret)
    local confFile=io.open(ret.conf)

    if confFile then
        ret.confAccess=lfs.attributes(ret.conf).permissions
        ret.infoStr=ret.infoStr..string.format("--confRead--Configuration file OPEN in %s\n", ret.conf)
        ret.limits={}
        local tmp
        local cur, prev=ret, ret
        for line in confFile:lines() do
            while true do
                local lineTbl=splitStr(line, "#")
                line=lineTbl[1]
                if string.len(line)~=0 then

                    tmp=setPropertyByMatch(cur, "ano",          line, [[<\s*Anonymous\s*(\S+)>]],   1)
                    if tmp then cur=tmp break end

                    tmp=setPropertyByMatch(cur, "dir",          line, [[<\s*Directory\s*(\S+)>]],   1)
                    if tmp then cur=tmp break end

                    tmp=setPropertyByMatch(ret, "limits",       line, [[<\s*Limit\s*(\S+)>]],       1)
                    if tmp then prev=cur cur=tmp  break end

                    if rex.match(line, [[<\/\s*Anonymous\s*>]])     then cur=ret        break end
                    if rex.match(line, [[<\/\s*Directory\s*>]])     then cur=ret        break end
                    if rex.match(line, [[<\/\s*Limit\s*>]])         then cur=prev       break end

                    if setPropertyByMatch(cur, "AllowFrom",  line, [[\s+Allow\s*form\s+(\S+)]])     then break end
                    if setPropertyByMatch(cur, "AllowUser",  line, [[\s+AllowUser\s+(\S+)]])        then break end
                    if setPropertyByMatch(cur, "DenyUser",   line, [[\s+DenyUser\s+(\S+)]])         then break end
                    if setPropertyByMatch(cur, "AllowGroup", line, [[\s+AllowGroup\s+(\S+)]])       then break end
                    if setPropertyByMatch(cur, "AllowAll",   line, [[\s+(AllowAll\s*\S*)]])         then break end
                    if setPropertyByMatch(cur, "DenyAll",    line, [[\s+(DenyAll\s*\S*)]])          then break end

                    if setPropertyByMatch(cur, "Port",          line, [[Port\s+(\S*)]])             then break end
                    if setPropertyByMatch(cur, "AllowOverwrite",line, [[AllowOverwrite\s+(\S*)]])   then break end
                    -- if setPropertyByMatch(cur, "RuntimeUser",   line, [[User\s+(\S*)]])             then break end
                    -- if setPropertyByMatch(cur, "RuntimeGroup",  line, [[Group\s+(\S*)]])            then break end
                    if setPropertyByMatch(cur, "AuthOrder",     line, [[AuthOrder\s+(\S*)]])        then break end
                    if setPropertyByMatch(cur, "RootLogin",     line, [[RootLogin\s+(\S*)]])        then break end
                    if setPropertyByMatch(cur, "ServerIdent",   line, [[ServerIdent\s+(\S*)]])      then break end
                    if setPropertyByMatch(cur, "DefaultRoot",   line, [[DefaultRoot\s+(\S*)]])      then break end
                    if setPropertyByMatch(cur, "AuthUserFile",  line, [[AuthUserFile\s+(\S*)]])     then break end
                    if setPropertyByMatch(cur, "AuthGroupFile", line, [[AuthGroupFile\s+(\S*)]])    then break end
                end
                break
            end
        end

        local passwdFile=io.open([[/etc/passwd]])
        if passwdFile then
            if ret.ano then
                setHomeDir(ret, ret.ano, passwdFile)
                setDirsPermissions(ret, ret.ano)
            end

            if ret.dir then
                setHomeDir(ret, ret.dir, passwdFile)
                setDirsPermissions(ret, ret.dir)
            end
            passwdFile:close()
        else
            ret.infoStr=ret.infoStr.."--confRead--/etc/passwd NOT OPENED\n"
        end

        confFile:close()
    else
        ret.confAccess=""
        ret.infoStr=ret.infoStr..string.format("--confRead--Configuration file NOT OPEN  in %s\n", ret.conf)
    end
end

function setHomeDir(ret, dirs, passwdFile)
    local paths={}
    for path, dir in pairs(dirs) do
        if string.find(path, "~")~=-1 then
            local user=rex.match(path, [[~(\S+)]])
            for line in passwdFile:lines() do
                local lineTbl=splitStr(line, ":")
                if user==lineTbl[1] then
                    table.insert(paths, path)
                    -- dirs[path]=nil
                    dirs[lineTbl[6]]=dir
                end
            end
        end
    end

    for _, path in pairs(paths) do
        dirs[path]=nil
    end
end

-- function setBina

function setDirsPermissions(ret, dirs)
    for path, dir in pairs(dirs) do
        local attrs, errMsg=lfs.attributes(path)
        if attrs then
            dir.permission=attrs.permissions
            ret.infoStr=ret.infoStr..string.format("--setDirsPermissions--%s permission get\n", path)
        else
            dir.permission=""
            ret.infoStr=ret.infoStr..string.format("--setDirsPermissions--Unable to get %s's permission: %s\n", path, errMsg)
        end
    end
end

function setVersion(ret)
    if ret.cmd then
        local verCmd=string.format("%s --version", ret.cmd)
        local verCode, verMsg=execute_shell(verCmd)
        if verCode==0 then
            ret.infoStr=ret.infoStr..string.format("--setVersion--Version command SUCCESS: %s.\n", verCmd)
            local ver=rex.match(verMsg, [[\d+\.\d+\S*]]) or ""
            ret.version=ver
        else
            ret.infoStr=ret.infoStr..string.format("--setVersion--Version command FAILED: %s, %s, %s.\n", verCmd, verCode, verMsg)
        end
    else
        ret.infoStr=ret.infoStr.."--setVersion--No proc proftpd is running\n"
    end
end

function setCmd(ret)
    if ret.pid then
        local readlink=string.format("readlink /proc/%s/exe", ret.pid)
        print(readlink)
        local cmdCode, cmdMsg=execute_shell(readlink)
        if cmdCode==0 then
            ret.cmd=rex.match(cmdMsg, [[\S+]])
            ret.infoStr=ret.infoStr..string.format("--setCmd--Readlink command SUCCESS: %s.\n", readlink)
        else
            ret.infoStr=ret.infoStr..string.format("--setCmd--Readlink command FAILED: %s, %s, %s.\n", readlink, cmdCode, cmdMsg)
        end
    else
        ret.infoStr=ret.infoStr.."--setCmd--No proc proftpd is running\n"
    end
end

function setVuls(ret)
    if ret.version then
        ret.vuls={}
        if ret.version=="1.3.5" then
            ret.vuls.CVE20153306=true
        else
            ret.vuls.CVE20153306=false
        end
    else
        ret.infoStr=ret.infoStr.."--setCmd--Unable to find version information\n"
    end

end

function proftp_check()
    local ret={}
    local proCode, ret=proc_check()

    if proCode==0 then
        setCmd(ret)
        setVersion(ret)
        setVuls(ret)
        confRead(ret)
    end
    agent.lua_print_r(ret)

    return 0, ret
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
    if one_cmd.name == "proftp_check" then
        tmp_code, tmp_msg = proftp_check() 
    end
    if tmp_code ~= 0 then
        msg_str = msg_str.." execute "..one_cmd.name.." error: "..tostring(tmp_code).." "
        local data = {args={uuid=json_tb.args.uuid},result=agent.base64_encode(cjson.encode(tmp_msg))}
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
        local data = {args={uuid=json_tb.args.uuid},result=agent.base64_encode(cjson.encode(tmp_msg))}
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

debugPrint("\n\n\n--script--Ends\n")
