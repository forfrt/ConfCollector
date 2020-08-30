--[[
Copyright: 2015-2016, qingteng 
File name: ssh_private_check.lua
Description: ssh private keys 检测
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
local execute_shell_l = common.execute_shell_l
local split = common.split
agent.load "rex_pcre"
local rex = rex_pcre
local socket = agent.require "socket"

if debug_on then
    json_str = [[{"args":{"uuid":"1","args":[{"name":"ssh_check","value":"check_redis"}]}}]]
end
local json_tb = cjson.decode(json_str)

function start_check()
    local tmp_tb = {}
    local cmd = "grep \"BEGIN RSA PRIVATE KEY\" /home/*/.ssh/* -l"
    local tmp_code, tmp_msg = execute_shell_l(cmd)
    if tmp_code == 0 and #tmp_msg > 0 then
        for _,line in pairs(tmp_msg) do
            tmp_tb[line] = true
        end
    end
    local cmd = "grep \"BEGIN RSA PRIVATE KEY\" /root/.ssh/* -l"
    local tmp_code, tmp_msg = execute_shell_l(cmd)
    if tmp_code == 0 and #tmp_msg > 0 then
        for _,line in pairs(tmp_msg) do
            tmp_tb[line] = true
        end
    end

    local key_path = {"~/readonly.key", "~/kps/kp-rlaht265-beta", "~/.key/100.pub", "~/60key", ".ssh/api.key", "~/.ssh/beta_relay_key", "/home/deploy/cms.key", "~/.ssh/coupon", "/root/.ssh/coupons", "/root/.ssh/deploy.key", "/home/rrxuser/.ssh/deploy.key", "~/.ssh/dev.key", "~/.ssh/dev-key", "/home/shell/.hadoop/hadoop_rsa", "/root/id_rsa", "/root/.ssh/id_rsa_readonly", "~/xuming/key/id_rsa_xuming", "~/key", "key/root/kp_id_rsa", "~/.ssh/kp-20reo2kv", "/root/.ssh/kp-avm77ys1-JiaoYi", "/root/kp-avm77ys1-JiaoYi", "/root/kp-docker", "/root/.ssh/kp-fjayd6k3-opsTiaoBanJi", "/root/kp-fjayd6k3-opsTiaoBanJi", "/root/kp-i3maqzdk", "/data/wujitaiji/kp-qxox3076", "/home/deploy/kp-qxox3076", "/root/kp-svfzmh91-online", "~/.ssh/keys/kp-svfzmh91-PrivateCloud-BBS", "/root/human/hxyJq/kp-tongji", "/home/yangkuo/kp-x2mh80ay", "tmp/kp-x2mh80ay", "~/Keys/kp-xfe-beta", "/home/user/lijj/mq/mq_rsa", "/root/user/nginx-outer-dev", "/root/user/outer-nginx-dev", "~/phone.key", "~/pro-push", "/root/push", "/root/.ssh/risk.prod.key", "/home/rrxuser/key/root.key", "/root/root.key", "~/.ssh/rrxuser.key", "~/rrxuser_key", "~/sns.key", "/root/xy_tpa_key_root", "/root/xy_tpa_key_rrxuser"}
    for i,path in pairs(key_path) do
        if string.sub(path, 1, 1) == "/" then
            if lfs.attributes(path, "mode") == "file" then
                local cmd = "grep -l \"BEGIN RSA PRIVATE KEY\" "..path
                local tmp_code, tmp_msg = execute_shell_l(cmd)
                if tmp_code == 0 and #tmp_msg == 1 then
                    tmp_tb[tmp_msg[1]] = true
                end
            end
        elseif string.sub(path, 1, 1) == "~" then
            local root_prefix = "/root"..string.sub(path, 2, -1)
            if lfs.attributes(root_prefix, "mode") == "file" then
                local cmd = "grep -l \"BEGIN RSA PRIVATE KEY\" "..root_prefix
                local tmp_code, tmp_msg = execute_shell_l(cmd)
                if tmp_code == 0 and #tmp_msg == 1 then
                    tmp_tb[tmp_msg[1]] = true
                end
            end
            for file in lfs.dir("/home") do
                if file ~= "." and file ~= ".." then
                    local user_prefix = "/home/"..file..string.sub(path, 2, -1)
                    if lfs.attributes(user_prefix, "mode") == "file" then
                        local cmd = "grep -l \"BEGIN RSA PRIVATE KEY\" "..user_prefix
                        local tmp_code, tmp_msg = execute_shell_l(cmd)
                        if tmp_code == 0 and #tmp_msg == 1 then
                            tmp_tb[tmp_msg[1]] = true
                        end
                    end
                end
            end
        end
    end
    local key_tb = {}
    for key_path,_ in pairs(tmp_tb) do
        table.insert(key_tb, key_path)
    end
    agent.lua_print_r(key_tb)
    return 0, cjson.encode(key_tb)
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
    if one_cmd.name == "ssh_check" then
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
        if not debug_on then
            tmp_code, http_code, tmp_msg = agent.post_json_to_srv(url, j_str, is_compress)
        end
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
        if not debug_on then
            tmp_code, http_code, tmp_msg = agent.post_json_to_srv(url, j_str, is_compress)
        end
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
