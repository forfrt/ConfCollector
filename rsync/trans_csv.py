import json
import re
import sys

reload(sys)
sys.setdefaultencoding('utf-8')

id_ip = {}
with open("./id_list_all","r") as f:
    for line in f:
        info = line.split()
        id_ip[info[0]] = info[1]
#print id_ip

with open("./success_log","r") as f: 
    rex = re.compile(r"76102255dfdfb28a5083\s*([^\n]*)")
    flag = False
    for line in f:
        one = rex.search(line)
        if one:
            one = one.group(1).split(" ",1)
            all_info = json.loads(one[1])
            print one[0]+",",id_ip[one[0]],",",
            for info in all_info:
                print info["user"],",",info["uid"],",",info["group"],",",info["gid"],",",\
                    info["start_type"],",",
                for mode in info["config"]:
                    if mode["mode_name"] == "GLOBAL":
                        print mode["mode_name"],",",mode["uid"],",",mode["gid"],",",mode["hosts_allow"],",",\
                            mode["auth_users"],",",mode["read_only"],",",
                for mode in info["config"]:
                    if mode["mode_name"] != "GLOBAL":
                        print mode["mode_name"],",",mode["uid"],",",mode["gid"],",",mode["hosts_allow"],",",\
                            mode["auth_users"],",",mode["read_only"],",",
                break
            print "\n",
