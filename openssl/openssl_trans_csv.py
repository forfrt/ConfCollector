import json
import re
import sys

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
    
def handleHome(homeStr):
    rex=re.compile(r'OPENSSLDIR: \"([^\s]*)"\n')
    home=rex.search(homeStr)
    print home.group(1), ",",

def handleSSL2(ssl, infoStr):
    if ssl==-2:
        if infoStr.find("--checkSSL2--unexpected result")!=-1:
            print "false,",
        else:
            print "true,", 
    else:
        print "false,",

def handleSSL3(ssl, infoStr):
    if ssl==-2:
        print "true,", 
    else:
        print "false,",

def handleVersion(version):
    CVE20140160=["1.0.1", "1.0.1a", "1.0.1b", "1.0.1c", "1.0.1d", "1.0.1e", "1.0.1f"]
    for i in CVE20140160:
        if version.find(i)!=-1:
            return True
        
    return False


displayKeys=['version', 'home', 'SSLv2', 'SSLv3', 'cveDB']
    
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
                    oneLeft=oneLeft+one[index]+" "

            if oneLeft.find('read file error')!=-1:
                continue

            all_info = json.loads(oneLeft)

            if type(all_info)==list:
                all_info=all_info[0]
            print one[0]+",",id_ip[one[0]],",",

            for disKey in displayKeys:
                if all_info.has_key(disKey):
                    if disKey=="home":
                        handleHome(all_info[disKey])
                    elif disKey=="SSLv2":
                        handleSSL2(all_info[disKey], all_info["infoStr"])
                    elif disKey=="SSLv3":
                        handleSSL3(all_info[disKey], all_info["infoStr"])
                    elif disKey=="version":
                        print all_info[disKey], ",", handleVersion(all_info[disKey]), ",",
                else:
                    print "", ",",
                    
            print "\n",
