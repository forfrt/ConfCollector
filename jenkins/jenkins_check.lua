--[[
Copyright: 2015-2016, qingteng 
File name: jenkins_check.lua
Description: jenkins 应用检查 
Author: chengdu 
Version: 1.0
Date: 2016.6.2

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

--TODO
--1. 端口号获取方式不对, 需要通过ps拿到pid后, 通过netstat获取其端口号. 然而netstat显示的端口号可能有多个, 提取方式有待研究
--2. getHtml中, 没有对可能出现的错误, 如timeout进行任何处理.
--3. cve版本比较函数中, 可以改为使用dictionary来存储cve版本检测, 以提高效率
--4. getHomedir部分, 可能存在代码忘记删除情况
--5. check4Files查文件 可能会耗时很久

local begin_time = os.time()
local common = agent.require "agent.platform.linux.common"
local execute_shell = common.execute_shell
local execute_shell_l=common.execute_shell_l
agent.load "rex_pcre"
local rex = rex_pcre
local split=common.split
local socket = agent.require "socket"
local jparser = agent.require "parser"
local curl = agent.require "curl"
local cfchk = agent.require "confchecker"
local DEBUG=nil

if debug_on then
    json_str = [[{"args":{"uuid":"1","args":[{"name":"jenkins_check","value":"/root"}]}}]]
end
local json_tb = cjson.decode(json_str)

function debugPrint(str)
    if DEBUG then print(str) end
end

function proc_check()
    local cmd = [[ps -eo pid,user,uid,group,gid,ucmd,cmd|awk '{if ($6=="java") print $0}']]
    local ret = {} 
    local jenkins_num = 1
    local tmp_code, proc_info_table = execute_shell_l(cmd)
    if tmp_code == 0 then
        for i,line in ipairs(proc_info_table) do
            local isJenkins = false
            local tmp = {}
            local divided_info = split(line, " ") 
            tmp.pid = divided_info[1] 
            tmp.user = divided_info[2] 
            local hsperfdata_path = "/tmp/hsperfdata_"..tmp.user.."/"..tmp.pid
            local hsperfdata_reader = io.open(hsperfdata_path, "r")
            if hsperfdata_reader then
                if lfs.attributes(hsperfdata_path, "size") == 32768 then
                    local tmp_code, tmp_msg = jparser.parse_perfdata(hsperfdata_reader:read("*all"))
                    
                    if tmp_code == 0 then
                        local jpname
                        if tmp_msg["sun.rt.javaCommand"] and tmp_msg["sun.rt.javaCommand"][2] then
                            jpname = string.match(tmp_msg["sun.rt.javaCommand"][2], [[%S*]])
                        end
                        if string.find(jpname,'jenkins') then
                           isJenkins = true 
                        end
                    end
                end
                hsperfdata_reader:close()
            end
            if isJenkins then
                ret[jenkins_num] = {} 
                ret[jenkins_num].pid = divided_info[1]
                ret[jenkins_num].user = divided_info[2]
                ret[jenkins_num].uid = divided_info[3]
                ret[jenkins_num].group = divided_info[4]
                ret[jenkins_num].gid = divided_info[5]
                ret[jenkins_num].ucmd = divided_info[6]
    
                ret[jenkins_num].cmd=""
                for var=7,#divided_info, 1 do
                    ret[jenkins_num].cmd=ret[jenkins_num].cmd..divided_info[var].." "
                end

                jenkins_num = jenkins_num+1
            end
        end
    else
        return -1, "proc check exec shell fail." 
    end
    if next(ret) == nil then 
        return 1, "No proc jenkins."
    else
        return 0, ret
    end 
end

function getTomcatAppDir(homeDir)
    local serverConfPath=string.format("%s/%s", homeDir, "conf/server.xml")
    local serverConf=io.open(serverConfPath)
    local appBase
    if serverConf then
        for line in serverConf:lines() do
            appBase=rex.match(line, [[appBase="([^"]*)"]])
            if appBase then return 0, appBase end
        end
    else
        return 1, "--getTomcatAppDir--Configuration file not found\n"
    end
end

function trimStr(str, del)
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

function getUserHomeDir(user)
    local passPath="/etc/passwd"
    local passFile=io.open(passPath)
    if passFile then
        for line in passFile:lines() do
            local tab=trimStr(line, ":")
            if tab[1]==user then
                passFile:close()
                return 0, tab[6]
            end
        end
    else
        return 1, "cannot access /etc/passwd"
    end

    passFile:close()
    return -1, "cannot fnd the specified user"
end

function isTomcatRunning()
    local cmd = [[ps -eo pid,user,uid,group,gid,ucmd,cmd|awk '{if ($6=="java") print $0}']]
    local ps_code, psInfoTable = execute_shell_l(cmd)
    local baseHome
    if ps_code == 0 then
        for i,psInfo in ipairs(psInfoTable) do
            local baseHome=rex.match(psInfo, [[catalina\.home=(\S*)]])
            if baseHome then
                local ret={}
                local dividedInfo = split(psInfo, " ") 
                ret.user=dividedInfo[2]
                ret.uid=dividedInfo[3]
                ret.group=dividedInfo[4]
                ret.baseHome=baseHome
                return 0, ret
            end
        end
    else
        return -1, "--isTomcatRunning--proc check exec shell fail\n"
    end

    if not baseHome then
        return 1, "--isTomcatRunning--No proc tomcat\n"
    end
    
end

function getTomcatUser(homeDir)
    local userPath=string.format("%s/%s", homeDir, "conf/tomcat-users.xml")
    local userFile=io.open(userPath)
    local ret={}
    ret.user={}
    ret.pass={}
    if userFile then
        for line in userFile:lines() do
            user, pass=rex.match(line, [[<user\s*username=\s*"([^"]*)"\s*password=\s*"([^"]*)"\s*roles=\s*"admin"\s*\/>]])
            if user and pass then
                table.insert(ret.user, user)
                table.insert(ret.pass, pass)
            end
        end
    else
        return 1, "tomcat-user.xml not found"
    end
    userFile:close()
    return 0, ret
end

function search4File(path, file1, file2, level)
    if level>2 then
        return nil
    end
    for file in lfs.dir(path) do
        if file~="." and file ~=".." then
            local f=path.."/"..file
            local attr=lfs.attributes(f)
            if type(attr)=="table" then
                if attr.mode=="directory" then
                    local ret=search4File(f, file1, file2, level+1)
                    if ret then return ret end
                else
                    if file==file1 or file==file2 then
                        return file
                    end
                end
            end
        end
    end
end

function getVersion(welHtml)
    local ver=rex.match(welHtml, [[Jenkins\s*ver\.\s*([^<>]*)]])
    
    if ver then
        return 0, ver
    end
    return 1, "--getVersion--Version not found\n"
end

function check4Vul(version)

    local CVE20168103="1.625.2"
    local CVE20160792="1.642.2"
    local CVE20160788="1.642.2"
    local CVE20157539="1.625.2"
    local CVE20151806="1.596.1"
    local CVE20143666="1.565.3"
    local cveDB={}

    cveDB["20168103"]=(version<CVE20168103)
    cveDB["20160792"]=(version<CVE20160792)
    cveDB["20160788"]=(version<CVE20160788)
    cveDB["20157539"]=(version<CVE20157539)
    cveDB["20151806"]=(version<CVE20151806)
    cveDB["20143666"]=(version<CVE20143666)

    return cveDB
end

--! tomcatUser, tomcatHome
function tomcatCheck()
    --! check if Tomcat is running or not
    runCode, runMsg=isTomcatRunning()
    local ret={}
    ret.infoStr=""
    resultInit(ret)
    if runCode==0 then
        ret.tomcatHome=runMsg.baseHome
        ret.tomcatUser=runMsg.user
        ret.tomcatUID=runMsg.uid
        ret.tomcatGroup=runMsg.group

        --! search for jenkins.war and ROOT.war under Tomat's webapp path
        local file=search4File(ret.tomcatHome, "jenkins.war", "ROOT.war", 1)
        if file=="" then
            ret.infoStr="No jenkins found in tomcat\n"
            return 1, ret
        end

        --! Get tomcat's openning port by reading the configuration file
        portCode, portMsg=getTomcatPort(ret.tomcatHome)
        if portCode==0 then
            ret.tomcatPort=portMsg
            ret.infoStr=string.format("--tomcatCheck--port found is %s", ret.tomcatPort)
        else
            res.infoStr=ret.infoStr..portMsg
        end

        local welUrl=""
        if file=="jenkins.war" then
            welUrl=string.format("127.0.0.1:%s/jenkins/", ret.tomcatPort)
        elseif file=="ROOT.war" then
            welUrl=string.format("127.0.0.1:%s", ret.tomcatPort)
        end

        --! Get the welcome page and check its title
        local welHtml=getHtml(welUrl)
        if welHtml~="" and jenkinsTitleCheck(welHtml) then
            ret.infoStr=ret.infoStr..string.format("The home html page found in %s\n", welUrl)

            --! find version information in welcome page
            verCode, verMsg=getVersion(welHtml)
            if verCode==0 then
                ret.version=verMsg
            else
                ret.infoStr=ret.infoStr..verMsg
            end

            -- check vuls by version number
            ret.cveDB=check4Vul(ret.version)

            -- check configuration page for Home directory
            local confUrl=string.format("%sconfigure", welUrl)
            local confHtml=getHtml(confUrl)
            local homeMsg
            ret.homeDir, homeMsg=getHomeDir(confHtml, ret.tomcatUser, "", 1)
            ret.infoStr=ret.infoStr..homeMsg
        else
            ret.homeDir='/root/.jenkins'
            ret.infoStr=ret.infoStr..string.format("The home html page not found in %s\n", welUrl)
        end

        -- check for configuration file
        local confCode, confMsg=confRead(ret.homeDir, ret)
        ret.infoStr=ret.infoStr..confMsg

        -- check the user and password configured in tomcat-user.xml
        local userCode, userMsg=getTomcatUser(ret.tomcatHome)
        if userCode==0 then
            ret.users=cjson.encode(userMsg)
        else
            ret.infoStr=userMsg
        end
    else
        ret.infoStr=ret.infoStr.."no tomcat running"
        return 1, ret
    end

    return 0, ret
end

function web_check()
    local tomCode, tomMsg=tomcatCheck()

    if tomCode==0 then
        return 0, tomMsg
    else
        return 1, tomMsg
    end
end

function jenkinsTitleCheck(str)
    local title=rex.match(str, [[<title>([^<]*)</title>]])

    if title then
        if string.find(string.lower(title), "jenkins") then
            return true
        end
    end
    return false
end

function checkUseSec(str)
    -- In the specification, The context in auth should be true
    local useSec=rex.match(str, [[<useSecurity>([^<>]*)</useSecurity]])
    if useSec then
        return useSec
    end
    return nil
end

function checkAuth(str)
    -- In the specification, The context in auth should be hudson.security.GlobalMatrixAuthorizationStrategy
    local auth=rex.match(str, [[authorizationStrategy\s*class="([^"]*)"]])
    if auth then
        return auth
    end
    return nil
end

function checkSecRealm(str)
    -- In the specification, The context in secRealm should be hudson.security.HudsonPrivateSecurityRealm
    local secRealm=rex.match(str, [[securityRealm\s*class="([^"]*)"]])
    if secRealm then
        return secRealm
    end
    return nil
end

function checkPermission(str, perTbl)
    local per=rex.match(str, [[<permission>([^<>]*)</permission>]])
    local delimiter
    local perKey, perValue
    if per then
        delimiter=string.find(per, ":")
        perKey=string.sub(per, 1, delimiter-1)
        perValue=string.sub(per, delimiter+1, -1)
        if not perTbl[perValue] then perTbl[perValue]={} end
        table.insert(perTbl[perValue], perKey)
    end
    
end

function checkSlave2Master(homePath)
    local switchPath=string.format("%s/%s", homePath, "secrets/slave-to-master-security-kill-switch")
    local switch=io.open(switchPath)
    if switch then
        local switchContent=switch:read("*a")
        switch:close()
        return 0, string.format("--checkSlaveMaster--The switch file found at %s: %s\n", switchPath, switchContent), switchContent
    end
    return 1, string.format("--checkSlaveMaster--The switch file not found at %s\n", switchPath), nil
end

-- userSec, auth, secRealm, permissions, slave
function confRead(homePath, tab)
    local confPath=string.format("%s/%s", homePath, "config.xml")
    local perTbl={}
    local confFile=io.open(confPath)
    local infoStr=""
    if not confFile then
        tab.homeDir=""
        return 1, string.format("--confRead--The configuration file at %s doesn't exists\n", confPath)
    end

    for line in confFile:lines() do
        tab.useSec  =tab.useSec     or checkUseSec(line)
        tab.auth    =tab.auth       or checkAuth(line)
        tab.secRealm=tab.secRealm   or checkSecRealm(line)
        checkPermission(line, perTbl)
    end
    if perTbl=={} then
        tab.permissions=""
        infoStr=infoStr.."--checkPermission--Permission not found in configuration file\n"
    else
        tab.permissions=cjson.encode(perTbl)
    end

    local slaCode, slaStr, slave=checkSlave2Master(homePath)
    if slaCode==1 then 
        infoStr=infoStr..slaStr
        tab.slave=""
    elseif slaCode==0 then
        infoStr=infoStr..slaStr
        tab.slave=slave
    end

    confFile:close()
    return 0, string.format("%s--confRead--The configuration found is located at %s\n", infoStr, confPath)
end

function getHtml(url)
    local html=""
    local c=curl.new()
    if not c then
        return "" 
    end
    c:setopt(curl.OPT_URL, url)
    c:setopt(curl.OPT_CONNECTTIMEOUT, 5)
    c:setopt(curl.OPT_WRITEFUNCTION, function(param, buffer)
        html=string.format("%s%s", html, buffer)
        return #buffer
    end)

    local perform=c:perform()
    if not perform then
        c:close()
        return ""
    end
    c:close()
    return html
end

function getPort(cmd)
    local port=rex.match(cmd, [[--httpPort=(\S*)]])
    if port then
        return port, string.format("--getPort--Port found in cmd is %s\n", port)
    end
    return nil, "--getPort--Port not found in cmd\n"
end

function getTomcatPort(homeDir)
    local serverPath=string.format("%s/conf/server.xml", homeDir)
    serverFile=io.open(serverPath)
    if serverFile then
        for line in serverFile:lines() do
            local port=rex.match(line, [[<Connector\s*port=\s*"([^"]*)"]])
            if port then
                serverFile:close()
                return 0, port
            end
        end
    else
        return 1, string.format("--getTomcatPort--server.xml not found in %s\n", serverPath)
    end

    serverFile:close()
    return -1, string.format("--getTomcatPort--No port found in %s\n", serverPath)
end

function getDefHome(user)
    local homeCode, homeMsg=getUserHomeDir(user)
    if homeCode~=0 then
        if string.lower(user)=="root" then
            return '/root/.jenkins'
        else
            return string.format("/home/%s/.jenkins", user)
        end
    else
        return homeMsg.."/.jenkins"
    end
end

function getCmdHomeDir(cmd)
    local homCmd=rex.match(cmd, [[-DJENKINS_HOME=(\S*)]])
    if homCmd then
        return 0, homCmd
    else
        return 1, string.format("--getCmdHomeDir--Home Directory not found in CMD: %s. Try reading configuration html instead\n", cmd)
    end
end

function getHtmlHomeDir(html)
--<td class="setting-name">Home directory</td><td class="setting-main">/root/.jenkins</td>

    local homeDir=rex.match(html, [[<td[^<>]*>Home\s*directory<\/td><td[^<>]*>([^<>]*)<\/td>]])
    if not homeDir then
        return homeDir, string.format("--getHomeDir--The configuration file not found in HTML. Use default home instead\n")
    else
        return homeDir, string.format("--getHomeDir--The configuration file found in HTML\n")
    end
end

function getHomeDirNoCmd(confHtml, user, cmd, infoStr)
    if confHtml=="" then
        return getDefHome(ret.tomcatUser), infoStr..string.format("The configuration html page not found in HTML %s. Use default home instead\n", confUrl)
    else
        --! Get the home dir by looking for the content in the configuration page
        local homeDir, homeMsg=getHtmlHomeDir(confHtml)
        if not homeDir then
            return getDefHome(user), infoStr..homeMsg
        else
            return homeDir, infoStr..homeMsg
        end
    end
end

function getHomeDir(confHtml, user, cmd, cmdFlag)
    local infoStr=""
    if cmdFlag==0 then
        local cmdCode, cmdMsg=getCmdHomeDir(cmd)
        if cmdCode==0 then
            return cmdMsg, string.format("--getHomeDir--Home Directory found in CMD: %s\n", cmd)
        else
            infoStr=infoStr..cmdMsg
        end
    end
    return getHomeDirNoCmd(confHtml, user, cmd, infoStr)
end

function resultInit(ret)
    if not ret.pid              then ret.pid            = "" end
    if not ret.user             then ret.user           = "" end
    if not ret.uid              then ret.uid            = "" end
    if not ret.group            then ret.group          = "" end
    if not ret.cmd              then ret.cmd            = "" end
    if not ret.gid              then ret.gid            = "" end
    if not ret.ucmd             then ret.ucmd           = "" end
    if not ret.port             then ret.port           = "" end
    if not ret.tomcatUser       then ret.tomcatUser     = "" end
    if not ret.tomcatUID        then ret.tomcatUID      = "" end
    if not ret.tomcatGroup      then ret.tomcatGroup    = "" end
    if not ret.tomcatHome       then ret.tomcatHome     = "" end
    if not ret.tomcatPort       then ret.tomcatPort     = "" end
end


function read_jar(file_path)
    if lfs.attributes(file_path, "mode") == "file" then 
        local tmp_code, tmp_msg = cfchk.unzip_read_current_file(file_path, "META-INF/MANIFEST.MF")
        --print(tmp_msg)
        if tmp_code == 0 then
            return tmp_msg
        else
            return ""
        end
    else
        return ""
    end
end

function getCmdVersion(cmd)
    local war=rex.match(cmd, [[-jar\s*(\S*)]])

    if war then
        local meta_info = read_jar(war)
        jp_version = rex.match(meta_info, [[Implementation\-Version\s*:\s*((?:\d+\.)+\d+)]])

        if jp_version then
            return 0, jp_version
        else
            return -1, string.format("--getCmdVersion--Version read from %s FAILED\n", war)
        end
    else
        return 1, "--getCmdVersion--Version information not found in cmd\n"
    end
end

function jenkins_check()
    --! check whether process jenkins exists or not
    
    local proc_code, proc_msg = proc_check()
    if proc_code==0 then
        for _, jenkins in pairs(proc_msg) do
            --! Give every column in the return table a defualt value
            resultInit(jenkins)

            --! Read the port information from its running command
            port, jenkins.infoStr=getPort(jenkins.cmd)
            if port then
                jenkins.port=port
            else
                jenkins.port="8080"
            end

            local verCode, verMsg=getCmdVersion(jenkins.cmd)
            local welUrl=string.format("127.0.0.1:%s/", jenkins.port)

            if verCode==0 then
                jenkins.version=verMsg
            else
                jenkins.infoStr=jenkins.infoStr..verMsg

                --! Get the welcome page
                local welHtml=getHtml(welUrl)
                if welHtml~="" and jenkinsTitleCheck(welHtml) then
                    jenkins.infoStr=jenkins.infoStr..string.format("The home html page found in %s\n", welUrl)

                    --! find version information in welcome page
                    verCode, verMsg=getVersion(welHtml)
                    if verCode==0 then
                        jenkins.version=verMsg
                    else
                        jenkins.infoStr=jenkins.infoStr..verMsg
                    end

                end
            end

            -- check vuls by version number
            if jenkins.version then
                jenkins.cveDB=check4Vul(jenkins.version)
            else
                jenkins.version=""
                jenkins.cveDB={}
            end

            --! Get the configuration page
            local confUrl=string.format("%sconfigure", welUrl)
            local confHtml=getHtml(confUrl)

            if confHtml~="" then
                local homeMsg
                jenkins.homeDir, homeMsg=getHomeDir(confHtml, jenkins.user, jenkins.cmd, 0)
                jenkins.infoStr=jenkins.infoStr..homeMsg
            else
                local homeCode, homeMsg=getCmdHomeDir(jenkins.cmd)
                if homeCode==0 then
                    jenkins.homeDir=homeMsg
                    jenkins.infoStr=jenkins.infoStr.."--getHomeDir--Home Directory found in cmd\n"
                else
                    jenkins.homeDir=getDefHome(jenkins.user)
                    jenkins.infoStr=jenkins.infoStr..homeMsg..string.format("The home html page not found in %s\n", welUrl)
                end
            end
            -- Read the configuration related to security 
            local confCode, confMsg=confRead(jenkins.homeDir, jenkins)
            jenkins.infoStr=jenkins.infoStr..confMsg
        end
        -- agent.lua_print_r(proc_msg)
        return proc_code, proc_msg
    elseif proc_code == -1 or proc_code==1 then
        local webCode, webMsg=web_check()
        -- agent.lua_print_r(webMsg)
        return webCode, webMsg
    end 

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
    if one_cmd.name == "jenkins_check" then
        tmp_code, tmp_msg = jenkins_check() 
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





