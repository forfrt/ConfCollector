--[[
Copyright: 2015-2016, qingteng 
File name: struts2_check.lua
Description: struts2漏洞检测
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
local cfchk = agent.require "confchecker"

if debug_on then
    json_str = [[{"args":{"uuid":"1","args":[{"name":"check_struts2","value":""}]}}]]
end
local json_tb = cjson.decode(json_str)

function check_s2_037(one_app_path)
    local vul_flag = false
    local cmd = "find \""..one_app_path.."\" -name struts2-rest-plugin*.jar"
    local tmp_code, tmp_msg = execute_shell_l(cmd)
    if tmp_code == 0 and #tmp_msg > 0 then
        vul_flag = true
    end
    return vul_flag
end

function check_xml(one_app_path, _type)
    local vul_flag = false
    local regex
    if _type == "S2-019" then
        regex = [[name\s*=\s*(?:"|')\s*struts\.devMode\s*(?:"|')\s*value\s*=\s*(?:"|')\s*true\s*(?:"|')]]
    elseif _type == "S2-032" then
        regex = [[name\s*=\s*(?:"|')\s*struts\.enable\.DynamicMethodInvocation\s*(?:"|')\s*value\s*=\s*(?:"|')\s*true\s*(?:"|')]]
    else
        return vul_flag
    end
    local cmd = "find \""..one_app_path.."\" -name struts.xml"
    local tmp_code, tmp_msg = execute_shell_l(cmd)
    if tmp_code == 0 and #tmp_msg > 0 then
        for _,xml in pairs(tmp_msg) do
            local f = io.open(xml)
            if f then
                for line in f:lines() do
                    if rex.match(line, regex) then
                        print(line)
                        vul_flag = true
                        break
                    end
                end
                f:close()
                if vul_flag then
                    break
                end
            end
        end
    end
    return vul_flag
end

function get_ver(file_path)
    local ver
    if lfs.attributes(file_path, "mode") == "file" then
        local tmp_code, tmp_msg = cfchk.unzip_read_current_file(file_path, "META-INF/MANIFEST.MF")
        if tmp_code == 0 and tmp_msg then
            ver = rex.match(tmp_msg, [[Specification\-Version\s*:\s*(\S*)]]) or ""
            return ver
        else
            ver = rex.match(file_path, [[struts2\-core\-((?:\d+\.)+\d+)\.jar]]) or ""
            return ver
        end
    else
        ver = rex.match(file_path, [[struts2\-core\-((?:\d+\.)+\d+)\.jar]]) or ""
        return ver
    end 
end

function check_vul(webapp_path)
    local all_webapp = {}
    for file in lfs.dir(webapp_path) do
        if file ~= "." and file ~= ".." then
            local abs_path = webapp_path..file
            if lfs.attributes(abs_path, "mode") == "directory" then
                local webapp = {}
                webapp.name = file
                local cmd = "ls "..abs_path.."/WEB-INF/lib/struts2-core*.jar"
                local tmp_code, tmp_msg = execute_shell(cmd)
                if tmp_code == 0 and tmp_msg ~= "" then
                    local jar_file = rex.match(tmp_msg, [[\s*(\S*)]])
                    local ver = get_ver(jar_file)
                    if ver ~= "" then
                        webapp.ver = ver
                        webapp.vul = {}
                        if ver >= "2.3.28.2" then
                            --no vul
                        elseif ver >= "2.0.0" then
                            if ver <= "2.1.8.1" then
                                table.insert(webapp.vul, "S2-005")
                            end
                            if ver <= "2.3.1.1" then
                                table.insert(webapp.vul, "S2-009")
                            end
                            if ver <= "2.3.14" then
                                table.insert(webapp.vul, "S2-013")
                            end
                            if ver <= "2.3.15" then
                                table.insert(webapp.vul, "S2-016")
                            end
                            if ver <= "2.3.15.1" then
                                if check_xml(abs_path, "S2-019") then
                                    table.insert(webapp.vul, "S2-019")
                                end
                            end
                            if ver <= "2.3.16" then
                                table.insert(webapp.vul, "S2-020")
                            end
                            if ver >= "2.3.20" and ver <= "2.3.28" and ver ~= "2.3.20.3" and 
                                ver ~= "2.3.24.3" then
                                if check_xml(abs_path, "S2-032") then
                                    table.insert(webapp.vul, "S2-032")
                                end
                            end
                            if ver >= "2.3.20" and ver <= "2.3.28.1" then
                                if check_s2_037(abs_path) then
                                    table.insert(webapp.vul, "S2-037")
                                end
                            end
                        end
                        table.insert(all_webapp, webapp)
                    end
                end
            end
        end
    end
    return all_webapp
end

function start_check()
    local all_tomcat = {}
    local cmd = "ps -ef|grep org.apache.catalina.startup.Bootstrap|grep -v grep"
    local tmp_code, tmp_msg = execute_shell_l(cmd)
    if tmp_code == 0 and #tmp_msg > 0 then
        for _,cmd in pairs(tmp_msg) do
            local one_tomcat = {}
            one_tomcat.cmd = cmd
            one_tomcat.info = ""
            local catalina_home = rex.match(cmd, [[-Dcatalina\.home=(\S*)]])
            if catalina_home then
                if string.sub(catalina_home, -1, -1) ~= "/" then
                    catalina_home = catalina_home.."/"
                end
                local server_xml = catalina_home.."conf/server.xml"
                local f = io.open(server_xml, "r")
                if f and lfs.attributes(server_xml, "mode") == "file" then
                    local webapp_path
                    local all_lines = {}
                    for line in f:lines() do
                        table.insert(all_lines, line)
                    end
                    f:close()
                    for i=#all_lines,1,-1 do
                        local line = all_lines[i]
                        webapp_path = webapp_path or rex.match(line, [[<Host[^>]*?appBase\s*=\s*(?:"|')*\s*(\S*)(?:"|')]])
                        if webapp_path then
                            break
                        end
                    end
                    webapp_path = webapp_path or "webapps/"
                    if string.sub(webapp_path, -1, -1) ~= "/" then
                        webapp_path = webapp_path.."/"
                    end
                    --if webapp_path is absolute path
                    if string.sub(webapp_path, 1, 1) == "/" then
                        webapp_path = webapp_path
                    else
                        webapp_path = catalina_home..webapp_path
                    end
                    one_tomcat.webapp_path = webapp_path
                    if lfs.attributes(webapp_path, "mode") == "directory" then
                        one_tomcat.vul = check_vul(webapp_path)
                        table.insert(all_tomcat, one_tomcat)
                    else
                        one_tomcat.info = "can't find webapps directory"
                    end
                else
                    one_tomcat.info = "can't open server.xml"
                end
            end
        end
    end
    agent.lua_print_r(all_tomcat)
    return 0, cjson.encode(all_tomcat)
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
    if one_cmd.name == "check_struts2" then
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
