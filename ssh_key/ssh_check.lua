--[[
Copyright: 2015-2016, qingteng 
File name: ssh_check.lua
Description: ssh authorized_keys 检测
Author: wangzhen
Version: 1.0
Date: 2016.6.16


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
local common = agent.require "agent.platform.linux.common"
local execute_shell = common.execute_shell
local split = common.split
agent.load "rex_pcre"
local rex = rex_pcre
local socket = agent.require "socket"

if debug_on then
    json_str = [[{"args":{"uuid":"1","args":[{"name":"check_ssh","value":"check_redis"}]}}]]
end
local json_tb = cjson.decode(json_str)

function get_key_path()
    local key_path
    local ssh_conf = io.open("/etc/ssh/sshd_config")
    if ssh_conf then
        for line in ssh_conf:lines() do
            key_path = rex.match(line, [[^\s*AuthorizedKeysFile\s*(\S*)]])
            if key_path then
                break
            end
        end
        ssh_conf:close()
    end
    print(key_path)
    return key_path or ".ssh/authorized_keys"
end

function get_key(user, key_path)
    local key_num = 0
    local tmp_tb = {}
    local key_table = {}
    local hosts_table = {}
    local key_file, known_hosts
    if user == "root" then
        key_file = io.open("/root/"..key_path)
        known_hosts = io.open("/root/.ssh/known_hosts")
    else
        key_file = io.open("/home/"..user.."/"..key_path)
        known_hosts = io.open("/home/"..user.."/.ssh/known_hosts")
    end
    if key_file then
        for line in key_file:lines() do
            local info = split(line, " ")
            if #info > 2 then
                _type,commit = info[1],info[3]
            else
                _type,commit = info[1],""
            end
            key_num = key_num + 1
            table.insert(key_table, {type=_type,commit=commit})
        end
        key_file:close()
    end
    if known_hosts then
        if key_num > 0 then
            local host,_type
            for line in known_hosts:lines() do
                host,_type = rex.match(line, [[^(\S*)\s*(\S*)]])
                table.insert(hosts_table, {host=host,type=_type})
            end
        end
        known_hosts:close()
    end
    tmp_tb.user = user
    tmp_tb.key_table = key_table
    tmp_tb.hosts_table = hosts_table
    return key_num,tmp_tb
end

function start_check()
    local tmp_tb = {}
    local key_path = get_key_path()
    local key_num, key_tb = get_key("root",key_path)
    if key_num > 0 then
        table.insert(tmp_tb, key_tb)
    end
    for file in lfs.dir("/home") do
        if file ~= "." and file ~= ".." then
            key_num, key_tb = get_key(file, key_path)
            if key_num > 0 then
                table.insert(tmp_tb, key_tb)
            end
        end
    end
    return 0, cjson.encode(tmp_tb)
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
    if one_cmd.name == "check_ssh" then
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
