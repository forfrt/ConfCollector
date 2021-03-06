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
    
def handleGroups(groups, prepend, tcp='', x11=''):
    if type(groups)==dict:
        for name, group in groups.items():
            prepend1=name+","
            #prepend2=""
            for key in groupKeys:
                if group.has_key(key):
                    if key=="tcp4warding":
                        tcp=group[key]
                        #prepend2=prepend2+group[key]+","
                    elif key=="x114warding":
                        x11=group[key]
                        #prepend2=prepend2+group[key]+","
                    elif key=="users":
                        if type(group["users"])==dict:
                            handleUsers(group["users"], prepend+prepend1, tcp, x11)
    else:
        print prepend+",", 

def handleUsers(users, prepend, tcp='', x11=''):
    if type(users)==dict:
        for name, user in users.items():
            print prepend+name+",", 
            for key in userKeys:
                if user.has_key(key):
                    print user[key]+",", 
                else:
                    if key=="tcp4warding":
                       print tcp+",",
                    elif key=="x114warding":
                        print x11+",",
                    else:
                        print ",",
            print ""
    else:
        print ",,,,,",  

groupKeys=["users", "tcp4warding", "x114warding"]
userKeys=["tcp4warding", "x114warding", "chrootDir", "logIn"]
displayKeys=["AllowUser", "DenyUser", "AllowGroup", "AllowAll", "DenyAll", "Port", "RuntimeUser", "RuntimeGroup", "AuthOrder", "RootLogin", "ServerIdent", "DefaultRoot", "DefaultRoot", "AuthUserFile", "AuthGroupFile"]
    
with open("./result.log","r") as f: 
    rex = re.compile(r"76102255dfdfb28a5083([^\n]*)")
    flag = False
    print "AgentID,IP,", 
    for disKey in displayKeys:
        print disKey, ",",
    print "\n",

    for line in f:
        one = rex.search(line)
        if one:
            one = one.group(1).split(" ", 1)
            oneLeft=one[1]

            if oneLeft.find("--procCheck--Proc check exec shell fail")!=-1:
                continue

            if oneLeft.find("read file error")!=-1:
                continue
            
            all_info = json.loads(oneLeft)

            prepend=one[0]+","+id_ip[one[0]]+","
            for disKey in displayKeys:
                if all_info.has_key(disKey):
                    prepend=prepend+all_info[disKey]+"," 
                else:
                    prepend=prepend+"," 

            tcp=all_info.get("tcp4warding", "")
            x11=all_info.get("x114warding", "")

            if all_info.has_key("limits"):
                handleLimits(all_info["limits", prepend])

            if all_info.has_key("dir"):
                handleDir(all_info["groups"], prepend)

            if all_info.has_key("ano"):
                handleAno(all_info["users"], prepend)
            print ""










 
