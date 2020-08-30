--[[
Copyright: 2015-2016, qingteng 
File name: vsftpd_check.lua
Description: vsftpd配置检测
Author: wangzhen
Version: 1.0
Date: 2016.6.28


Input:
{   
    "args":
    {
        "uuid":"",
        "args":[{"name":Name, "value":Value}]
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
local soft = agent.require "agent.platform.linux.soft"
local common = agent.require "agent.platform.linux.common"
local execute_shell_l = common.execute_shell_l
local execute_shell = common.execute_shell
local split = common.split
agent.load "rex_pcre"
local rex = rex_pcre
local socket = agent.require "socket"

if debug_on then
    json_str = [[{"args":{"uuid":"1","args":[{"name":"vsftpd_check","value":""}]}}]]
end
local json_tb = cjson.decode(json_str)

function get_user_list(userlist_file)
    local userlist = ""
    local f = io.open(userlist_file, "r")
    if f and lfs.attributes(userlist_file,"mode") == "file" then
        for line in f:lines() do
            if rex.match(line, [[^\s*[^#]+]]) then
                local user = rex.match(line, [[^\s*(\S*)]])
                if user then
                    userlist = userlist..user.."|"
                end
            end
        end
        f:close()
    end
    return userlist
end

function get_conf(conf_file)
    local t = {}
    local f = io.open(conf_file, "r")
    if f then
        all_lines = {}
        for line in f:lines() do
            table.insert(all_lines, line)
        end
        for i=#all_lines,1,-1 do
            line = all_lines[i]
            if rex.match(line, [[^\s*[^#]+]]) then
                --anonymous users permission check
                t.anonymous_enable = t.anonymous_enable or 
                    rex.match(line, [[^\s*anonymous_enable\s*=\s*(\S*)]])
                t.anon_upload_enable = t.anon_upload_enable or 
                    rex.match(line, [[^\s*anon_upload_enable\s*=\s*(\S*)]])
                t.anon_mkdir_write_enable = t.anon_mkdir_write_enable or
                    rex.match(line, [[^\s*anon_mkdir_write_enable\s*=\s*(\S*)]])
                t.anon_other_write_enable = t.anon_other_write_enable or
                    rex.match(line, [[^\s*anon_other_write_enable\s*=\s*(\S*)]])
                --local users permission check
                t.local_enable = t.local_enable or
                    rex.match(line, [[^\s*local_enable\s*=\s*(\S*)]])
                t.write_enable = t.write_enable or
                    rex.match(line, [[\s*write_enable\s*=\s*(\S*)]])
                t.local_umask = t.local_umask or
                    rex.match(line, [[\s*local_umask\s*=\s*(\S*)]])
                t.chroot_local_user = t.chroot_local_user or
                    rex.match(line, [[^\s*chroot_local_user\s*=\s*(\S*)]])
                --visit permission
                t.userlist_enable = t.userlist_enable or 
                    rex.match(line, [[^\s*userlist_enable\s*=\s*(\S*)]])
                t.userlist_deny = t.userlist_deny or 
                    rex.match(line, [[^\s*userlist_deny\s*=\s*(\S*)]])
                t.userlist_file = t.userlist_file or
                    rex.match(line, [[^\s*userlist_file\s*=\s*(\S*)]])
                
                t.xferlog_enable = t.xferlog_enable or
                    rex.match(line, [[^\s*xferlog_enable\s*=\s*(\S*)]])
            end
        end
        f:close()
        --set default value, see "man vsftpd.conf"
        t.anonymous_enable = t.anonymous_enable or "YES"
        t.anon_upload_enable = t.anon_upload_enable or "NO"
        t.anon_mkdir_write_enable = t.anon_mkdir_write_enable or "NO"
        t.anon_other_write_enable = t.anon_other_write_enable or "NO"
        
        t.local_enable = t.local_enable or "NO"
        t.write_enable = t.write_enable or "NO"
        t.local_umask = t.local_umask or "077"
        t.chroot_local_user = t.chroot_local_user or "NO"
        
        t.userlist_enable = t.userlist_enable or "NO"
        t.userlist_deny = t.userlist_deny or "YES"
        t.userlist_file = t.userlist_file or "/etc/vsftpd/user_list"
        if t.userlist_enable == "YES" then
            t.userlist = get_user_list(t.userlist_file)
        else
            t.userlist = ""
        end
        
        t.xferlog_enable = t.xferlog_enable or "NO"
    end
    return t
end

function get_ver(pid)
    local cmd = "readlink -n /proc/"..pid.."/exe"
    local tmp_code, tmp_msg = execute_shell(cmd)
    local bin_path
    if tmp_code == 0 then
        bin_path = tmp_msg
    end
    bin_path = bin_path or ""

    local rpm_flag = soft.get_rpm_flag()
    local dpkg_flag = soft.get_dpkg_flag()
    local ver
    if rpm_flag then
        local cmd = "rpm -qf --queryformat=\"%{=VERSION}\" "..bin_path
        local tmp_code,tmp_msg = execute_shell(cmd)
        if tmp_code == 0 and tmp_msg ~= "" then
            ver = tmp_msg
        end
    elseif dpkg_flag then
        local cmd = "dpkg-query --search "..bin_path.." | awk -F \":\" '{if(NR == 1) print \$1}'"
        local tmp_code, tmp_msg = execute_shell(cmd)
        if tmp_code == 0 then
            tmp_msg = tmp_msg or ""
            ver = rex.match(tmp_msg, [[\s*(\S*)]])
        end
    end
    ver = ver or ""
    return ver
end

function get_port(pid)
    local cmd = "netstat -tunlp|grep "..pid.."|awk '{print $4}'|awk -F: '{print $2}'"
    local tmp_code, tmp_msg = execute_shell(cmd)
    if tmp_code == 0 then
        local port = rex.match(tmp_msg, [[^\s*(\S*)]])
        port = port or ""
        return port
    else
        return ""
    end
end

function get_abs_path(conf_path, pid)
    local conf_file
    local cmd = "ls -l /proc/"..pid.."/cwd"
    local tmp_code, tmp_msg = execute_shell(cmd)
    if tmp_code == 0 and tmp_msg ~= "" then
        local preffix = rex.match(tmp_msg, [[->\s*(\S*)\s*$]])
        if preffix then
            conf_file = preffix.."/"..conf_path
        end
    end
    return conf_file
end

function start_check()
    local all_ftp = {}
    local cmd = "ps -eo uname,uid,gid,pid,ucmd,cmd|grep vsftpd|grep -v grep"
    local tmp_code, tmp_msg = execute_shell_l(cmd)
    if tmp_code == 0 and #tmp_msg > 0 then
        for _,line in pairs(tmp_msg) do
            local info = split(line, " ")
            if info[5] == "vsftpd" then
                local one_ftp = {}
                one_ftp.user = info[1]
                one_ftp.uid = info[2]
                one_ftp.gid = info[3]
                one_ftp.port = get_port(info[4])
                one_ftp.cmd = ""
                for i=6,#info do
                    one_ftp.cmd = one_ftp.cmd..info[i].." "
                end
                one_ftp.version = get_ver(info[4])
                print(one_ftp.cmd)
                one_ftp.conf_file = rex.match(one_ftp.cmd, [[\s+([^=]*)\s+]]) or "/etc/vsftpd/vsftpd.conf"
                if string.sub(one_ftp.conf_file, 1, 1) ~= "/" then
                    one_ftp.conf_file = get_abs_path(one_ftp.conf_file, info[4]) or one_ftp.conf_file
                end
                one_ftp.config = get_conf(one_ftp.conf_file)
                table.insert(all_ftp, one_ftp)
            end
        end
    else
        return 1, "no vsftpd running"
    end
    --agent.lua_print_r(all_ftp)
    return 0, cjson.encode(all_ftp)
end


local tmp_code, tmp_msg
local msg_str = ""
local host = agent.get_erlang_data_server_host()
--local host = "https://123.59.87.121:8443"
if string.sub(host, -1, -1) ~= "/" then
    host = host.."/"
end
local url = host.."api/v1/data_collection"
for _,one_cmd in pairs(json_tb.args.args) do
    local cmd = ""
    if one_cmd.name == "vsftpd_check" then
        tmp_code, tmp_msg = start_check()
    end
    if tmp_code ~= 0 then
        msg_str = msg_str.." execute "..one_cmd.name.." error: "..tostring(tmp_code).." "..
            tostring(tmp_msg)
        local data = {args={uuid=json_tb.args.uuid},result=agent.base64_encode(msg_str)}
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
        print(tmp_code, http_code, tmp_msg)
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
