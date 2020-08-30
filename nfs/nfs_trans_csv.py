import json
import re
import sys

# TODO 

reload(sys)
sys.setdefaultencoding('utf-8')

id_ip = {}
with open("./id_list_all.all","r") as f:
    for line in f:
        info = line.split()
        id_ip[info[0]] = info[1]
#print id_ip

def showDic(dic):
    for (k, v) in dic.items():
        print "dic[%s]=%s" % (k, v)

def showLis(lis):
    for li in lis:
        print li
    
displayKeys=['1', 'confs']
def handleConfs(confs, runFlag, prepend):
    if type(confs)==dict:
        for (k, v) in confs.items():
            for (kv, vv) in v.items():
                print prepend, "," ,runFlag, ",", k, ",",  kv, ",",
                for confsKey in confsKeys:
                    if vv.has_key(confsKey):
                        print vv[confsKey], ",", 
                    else:
                        print ",",

                print "\n",

confsKeys=["access", "mapping", "secure", "sync", "wdelay", "subtree"]


displayKeys=['1', 'confs']
    
with open("./result.log","r") as f: 
#with open("./success_log","r") as f: 
    rex = re.compile(r"76102255dfdfb28a5083([^\n]*)")
    flag = False
    for disKey in displayKeys:
        print disKey, ",",

    print "\n",

    for line in f:
        one = rex.search(line)
        if one:
            one = one.group(1).split()
            oneLeft=""
            for index in range(len(one)):
                if index!=0:
                    if index==1:
                        oneLeft=oneLeft+one[index]
                    else:
                        oneLeft=oneLeft+" "+one[index]

            if oneLeft.find("--procCheck--Proc check exec shell fail")!=-1:
                continue
            
            all_info = json.loads(oneLeft)

            isRun=False
            prepend=""
            for disKey in displayKeys:
                if all_info.has_key(disKey):
                    if disKey=="1":
                        isRun=True
                        prepend=one[0]+","+id_ip[one[0]]
                    elif disKey=="confs":
                        handleConfs(all_info["confs"], isRun, prepend)
                else:
                    print ",",
                    
# [2016-06-18 14:48:58,468] INFO [job_result:163] 76102255dfdfb28a5083 21dafab12bb116ca [{"pid":"1215","homeDir":"\/var\/lib\/jenkins","cmd":"\/etc\/alternatives\/java -Dcom.sun.akuma.Daemon=daemonized -Djava.awt.headless=true -DJENKINS_HOME=\/var\/lib\/jenkins -jar \/usr\/lib\/jenkins\/jenkins.war --logfile=\/var\/log\/jenkins\/jenkins.log --webroot=\/var\/cache\/jenkins\/war --daemon --httpPort=9000 --ajp13Port=8009 --debug=5 --handlerCountMax=100 --handlerCountMaxIdle=20 --prefix=\/jenkins_1\/ ","tomcatHome":"","tomcatUser":"","ucmd":"java","user":"root","infoStr":"--getPort--Port found in cmd is 9000\n--getHomeDir--Home Directory found in cmd\n--confRead--The configuration found is located at \/var\/lib\/jenkins\/config.xml\n","permissions":"{\"zhangshibiao\":[\"hudson.model.Computer.Build\",\"hudson.model.Hudson.Administer\",\"hudson.model.Hudson.Read\",\"hudson.model.Item.Build\",\"hudson.model.Item.Read\"],\"zhenghw\":[\"hudson.model.Computer.Build\",\"hudson.model.Hudson.Read\",\"hudson.model.Item.Build\",\"hudson.model.Item.Read\"],\"huxh\":[\"hudson.model.Computer.Build\",\"hudson.model.Hudson.Administer\",\"hudson.model.Hudson.Read\",\"hudson.model.Item.Build\",\"hudson.model.Item.Read\"],\"liangpengfei\":[\"hudson.model.Computer.Build\",\"hudson.model.Hudson.Read\",\"hudson.model.Item.Build\",\"hudson.model.Item.Read\"],\"xujx\":[\"hudson.model.Computer.Build\",\"hudson.model.Hudson.Read\",\"hudson.model.Item.Build\",\"hudson.model.Item.Read\"],\"s_xingxin\":[\"hudson.model.Computer.Build\",\"hudson.model.Hudson.Read\",\"hudson.model.Item.Build\",\"hudson.model.Item.Read\"],\"zhaobin\":[\"hudson.model.Computer.Build\",\"hudson.model.Hudson.Read\",\"hudson.model.Item.Build\",\"hudson.model.Item.Read\"],\"liudong\":[\"hudson.model.Computer.Build\",\"hudson.model.Hudson.Read\",\"hudson.model.Item.Build\",\"hudson.model.Item.Read\"],\"hanxd\":[\"hudson.model.Computer.Build\",\"hudson.model.Hudson.Read\",\"hudson.model.Item.Build\",\"hudson.model.Item.Read\"],\"xiath\":[\"hudson.model.Computer.Build\",\"hudson.model.Hudson.Read\",\"hudson.model.Item.Build\",\"hudson.model.Item.Read\"],\"guofei\":[\"hudson.model.Computer.Build\",\"hudson.model.Hudson.Read\",\"hudson.model.Item.Build\",\"hudson.model.Item.Read\"],\"anonymous\":[\"hudson.model.Hudson.Read\",\"hudson.model.Item.Read\"],\"chenke\":[\"hudson.model.Computer.Build\",\"hudson.model.Hudson.Administer\",\"hudson.model.Hudson.Read\",\"hudson.model.Item.Build\",\"hudson.model.Item.Read\"],\"yuhz\":[\"hudson.model.Computer.Build\",\"hudson.model.Hudson.Read\",\"hudson.model.Item.Build\",\"hudson.model.Item.Read\"],\"wujt\":[\"hudson.model.Computer.Build\",\"hudson.model.Hudson.Administer\",\"hudson.model.Hudson.Read\",\"hudson.model.Item.Build\",\"hudson.model.Item.Read\"],\"admin\":[\"hudson.model.Hudson.Administer\"],\"zhanglla\":[\"hudson.model.Hudson.Administer\"],\"wangyl@jiedaibao.com\":[\"hudson.model.Computer.Build\",\"hudson.model.Hudson.Read\",\"hudson.model.Item.Build\",\"hudson.model.Item.Read\"],\"human\":[\"hudson.model.Hudson.Administer\"],\"pengjk\":[\"hudson.model.Computer.Build\",\"hudson.model.Hudson.Administer\",\"hudson.model.Hudson.Read\",\"hudson.model.Item.Build\",\"hudson.model.Item.Read\"],\"tanjw\":[\"hudson.model.Computer.Build\",\"hudson.model.Hudson.Administer\",\"hudson.model.Hudson.Read\",\"hudson.model.Item.Build\",\"hudson.model.Item.Read\"]}","tomcatPort":"","uid":"0","secRealm":"hudson.security.HudsonPrivateSecurityRealm","gid":"0","group":"root","useSec":"true","port":"9000","auth":"hudson.security.GlobalMatrixAuthorizationStrategy"}]
