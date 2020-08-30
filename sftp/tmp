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
--http://blog.hylogics.com/entry/centos_sftpserver
--http://www.zhukun.net/archives/7641


local begin_time = os.time()
local common = agent.require "agent.platform.linux.common"
local execute_shell = common.execute_shell
local execute_shell_l=common.execute_shell_l
agent.load "rex_pcre"
local split=common.split
local rex = rex_pcre
local DEBUG=nil

if debug_on then
    json_str = [[{"args":{"uuid":"1","args":[{"name":"sftp_check","value":"/root"}]}}]]
end
local json_tb = cjson.decode(json_str)

function debugPrint(str)
    if DEBUG then print(str) end
end

function proc_check()
    local cmd = [[ps -eo pid,user,uid,group,gid,ucmd,cmd|awk '{if ($6=="sshd") print $0}']]
    local ret = {} 
    local tmp_code, proc_info_table = execute_shell_l(cmd)
    if tmp_code == 0 then
        ret.infoStr=string.format("--proc_check--exec shell succeed: %s.\n", cmd)
        for i,line in ipairs(proc_info_table) do
            local cmdPath=""
            local dividedInfo = split(line, " ") 
            for i=7,#dividedInfo, 1 do
                cmdPath=cmdPath..dividedInfo[i].." "
            end

            cmdPath=rex.match(cmdPath, [[((\/+\w*)+sshd)]])
            if cmdPath then
                ret.ps      = line
                ret.cmd     = cmdPath

                ret.pid     = dividedInfo[1]
                ret.user    = dividedInfo[2]
                ret.uid     = dividedInfo[3]
                ret.group   = dividedInfo[4]
                ret.gid     = dividedInfo[5]
                ret.ucmd    = dividedInfo[6]
            end
        end
    else
        ret.infoStr=string.format("--proc_check--exec shell fail: %d, %s, %s.\n", tmp_code, table.concat(pro_info_table), cmd)
        return -1, ret
    end

    if ret.pid == nil then 
        ret.infoStr=string.format("--proc_check--No proc sftp in running command: %s.\n", cmd)
        return 1, ret
    else
        return 0, ret
    end 
end

-- Check the version of openssl used in $PATH
function checkVer(ret)
    if ret.cmd then
        ret.infoStr=ret.infoStr..string.format("--checkVer--cmd FOUND\n")
    else
        local sshdFile=io.open("/usr/sbin/sshd")
        if sshdFile then
            ret.infoStr=ret.infoStr..string.format("--checkVer--cmd set to DEFAULT\n")
            ret.cmd="/usr/sbin/sshd"
        else
            ret.infoStr=ret.infoStr..string.format("--checkVer--cmd NOT FOUND\n")
            return
        end
    end

    local verCmd=string.format([[rpm -qf %s]], ret.cmd)
    local verCode, verMsg=execute_shell(verCmd)
    local version
    if verCode==0 then
        ret.infoStr=ret.infoStr..string.format("--checkVer--cmd executed SUCCESS: %s\n", verMsg)
        version=rex.match(verMsg, [[openssh\S*(\d+\.\d+[^\s,]*)]])
        if version then
            debugPrint(string.format("--checkVer--Version is %s\n", version))
            ret.version=version
            return 0
        end
    end
    ret.infoStr=ret.infoStr..string.format("--checkVer--cmd executed FAILED: %s, %s\n", verCode, verMsg)

    verCmd=string.format("%s %s", ret.cmd, "-v")
    verCode, verMsg=execute_shell(verCmd)
    if verCode==0 or verCode==1 then
        version=rex.match(verMsg, [[OpenSSH_([^\s,]*)]])
        if version then
            debugPrint(string.format("--checkVer--Version is %s\n", version))
            ret.version=version
            return 0
        end

        debugPrint(string.format("--checkVer--Version is %d, %s, %s\n", verCode, verCmd, table.concat(msg)))
        ret.version=table.concat(msg)
        return 0
    else
        ret.infoStr=ret.infoStr..string.format("--checkVer--exec shell fail: %d, %s, %s\n", verCode, verMsg, verCmd)
        return 1
    end
end

function setConf(ret)
    if ret.cmd then
        ret.infoStr=ret.infoStr..string.format("--setConfFromCmd--cmd FOUND\n")
        local confPath=rex.match(ret.cmd, [[-f\s*(\S*)]])
        if confPath then
            ret.conf=confPath
            ret.infoStr=ret.infoStr..string.format("--setConfFromCmd--Configuration file location FOUND in CMD: %s\n", confPath)
        else
            ret.conf="/etc/ssh/sshd_config"
            ret.infoStr=ret.infoStr..string.format("--setConfFromCmd--Configuration file location NOT FOUND in CMD and set to DEFAULT\n")
        end
    else
        ret.conf="/etc/ssh/sshd_config"
        ret.infoStr=ret.infoStr..string.format("--setConfFromCmd--cmd NOT FOUND and set to DEFAULT\n")
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

function setChrootPermissions(path, user, ret)
    chrootDir=io.open(path)
    if chrootDir then
        user.chrootPer=lfs.attributes(path).permissions
        ret.infoStr=ret.infoStr..string.format("--setChrootPermissions--ChrootDir OPENED %s\n", path)
    else
        user.chrootPer=""
        ret.infoStr=ret.infoStr..string.format("--setChrootPermissions--ChrootDir NOT OPENED %s\n", path)
    end
end

--users table
--groups table
--rootPermit string
--emptyPermit string
--allowUsers
--allowGroups
--denyUsers
--denyGroups
-- http://renlifeng.blog.51cto.com/2076113/637903
-- http://www.wanglifeng.info/sysadmin/openssh-sftp-setting.html
-- http://www.mrliangqi.com/514.html
function confRead(ret)
    setConf(ret)
    --setConfFromCmd(ret, ret.cmd)
    --setDefaultConf(ret)

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
                local lineTbl=splitStr(line, "#")
                line=lineTbl[1]

                if userFlag then
                    if setPropertyByMatch(ret.users[user], "chrootDir",      line, [[\s+ChrootDirectory\s+(\S+)]])      then 
                        setChrootPermissions(ret.users[user].chrootDir, ret.users[user], ret) 
                        break 
                    end
                    -- if setPropertyByMatch(ret.users[user], "x114warding",    line, [[\s+X11Forwarding\s+(\S+)]])        then break end
                    -- if setPropertyByMatch(ret.users[user], "tcp4warding",    line, [[\s+AllowTcpForwarding\s+(\S+)]])   then break end

                elseif groupFlag then
                    if setPropertyByMatch(ret.groups[group], "chrootDir",      line, [[\s+ChrootDirectory\s+(\S+)]])    then
                        setChrootPermissions(ret.groups[group].chrootDir, ret.groups[group], ret) 
                        break 
                    end
                    -- if setPropertyByMatch(ret.groups[group], "x114warding",    line, [[\s+X11Forwarding\s+(\S+)]])      then break end
                    -- if setPropertyByMatch(ret.groups[group], "tcp4warding",    line, [[\s+AllowTcpForwarding\s+(\S+)]]) then break end
                end

                tmpUser=rex.match(line, [[Match\s+User\s+(\S+)]])
                if tmpUser then
                    user=tmpUser
                    ret.users[user]={}
                    -- userFlag, groupFlag=true, false
                    userFlag=true
                    groupFlag=false
                    break
                end

                tmpGroup=rex.match(line, [[Match\s+Group\s+(\S+)]])
                if tmpGroup then
                    group=tmpGroup
                    ret.groups[group]={}
                    ret.groups[group].users={}
                    -- groupFlag, userFlag=true, false
                    userFlag=false
                    groupFlag=true
                    break
                end

                if setPropertyByMatch(ret, "subsystem",     line, [[Subsystem\s+(sftp\s+\S*)]])     then userFlag, groupFlag=false, false break end
                if setPropertyByMatch(ret, "force",         line, [[ForceCommand\s+(\S*)]])         then userFlag, groupFlag=false, false break end
                if setPropertyByMatch(ret, "chrootDir",     line, [[ChrootDirectory\s+(\S+)]])   then userFlag, groupFlag=false, false break end
                if setPropertyByMatch(ret, "allowUsers",    line, [[AllowUsers\s+([^\n]+)]])        then userFlag, groupFlag=false, false break end
                if setPropertyByMatch(ret, "allowGroups",   line, [[AllowGroups\s+([^\n]+)]])       then userFlag, groupFlag=false, false break end
                if setPropertyByMatch(ret, "denyUsers",     line, [[DenyUsers\s+([^\n]*)]])         then userFlag, groupFlag=false, false break end
                if setPropertyByMatch(ret, "denyGroups",    line, [[DenyGroups\s+([^\n]+)]])        then userFlag, groupFlag=false, false break end
                break
            end
        end

        local groupFile=io.open([[/etc/group]])
        if groupFile then
            ret.infoStr=ret.infoStr.."--confRead--/etc/group OPENED\n"
            getGIDByGroup(ret.groups, ret, groupFile)
            groupFile:close()
        else
            ret.infoStr=ret.infoStr.."--confRead--/etc/group NOT OPENED\n"
        end

        local passwdFile=io.open([[/etc/passwd]])
        if passwdFile then
            ret.infoStr=ret.infoStr.."--confRead--/etc/passwd OPENED\n"
            getUsersByGID(ret.groups, ret, passwdFile)
            getUserLogin(ret.groups, ret.users, ret, passwdFile)
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

function getUserLogin(groups, users, ret, passwdFile)
    ret.infoStr=ret.infoStr.."--getUserLogin--/etc/passwd OPENED\n"
    passwdFile:seek("set", 0)

    for line in passwdFile:lines() do
        local lineTbl=splitStr(line, ":")
        for name, group in pairs(groups) do
            for uName, user in pairs(group.users) do
                if uName==lineTbl[1] then
                    user.logIn=lineTbl[7]
                    if group.chrootDir=="%h" then
                        user.chrootDir=lineTbl[6]
                    elseif string.find(group.chrootDir, "%%u") then
                        user.chrootDir=string.gsub(group.chrootDir, "%%u", uName)
                    end
                    setChrootPermissions(user.chrootDir, user, ret) 
                end
            end
        end

        for name, user in pairs(users) do
            if name==lineTbl[1] then
                user.logIn=lineTbl[7]
                if user.chrootDir=="%h" then
                    user.chrootDir=lineTbl[6]
                elseif string.find(user.chrootDir, "%%u") then
                    user.chrootDir=string.gsub(user.chrootDir, "%%u", name)
                end
                setChrootPermissions(user.chrootDir, user, ret) 
            end
        end

    end
end

function getUsersByGID(groups, ret, passwdFile)
    for line in passwdFile:lines() do
        for _, group in pairs(groups) do
            local lineTbl=splitStr(line, ":")
            if group.GID==lineTbl[4] then
                -- table.insert(group.users, lineTbl[1])
                group.users[lineTbl[1]]={}
                -- print(string.format("User %s Found in Group %s", lineTbl[1], lineTbl[4]))
            end
        end
    end
        
end

function getGIDByGroup(groups, ret, groupFile)
    for line in groupFile:lines() do
        for name, group in pairs(groups) do
            local lineTbl=splitStr(line, ":")
            if name==lineTbl[1] then
                group.GID=lineTbl[3]
                -- print(string.format("Group ID %s Found in Group %s", lineTbl[3], lineTbl[1]))
            end
        end
    end
end

function sftp_check()
    local ret={}
    local proCode, ret=proc_check()
    if proCode==0 then
        checkVer(ret, ret.cmd)
        confRead(ret)
    end

    agent.lua_print_r(ret)
    return 0, ret
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
    if one_cmd.name == "sftp_check" then
        tmp_code, tmp_msg = sftp_check() 
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

