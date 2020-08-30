import json
import re

id_ip = {}
with open("./agent-info.csv","r") as f:
    for line in f:
        info = line.split(",")
        if info[1] != "0.0.0.0":
            id_ip[info[0]] = info[1]
        else:
            id_ip[info[0]] = info[2]

with open("./success_log","r") as f:
    rex = re.compile(r"76102255dfdfb28a5083([^\n]*)")
    flag = False
    for line in f:
        one = rex.search(line)
        if one:
            one = one.group(1).split()
            info = json.loads(one[1])
            print one[0]+",",id_ip[one[0]],",",
            #group, read_permission, conf_path, uname, pwd, bin_path, weak_pwd, bindip, port, ver, uid,
            print info["uname"]+",", str(info["uid"])+",", info["group"]+",", info["bin_path"]+",",\
                info["conf_path"]+",", info["read_permission"]+",", info["pwd"]+",",\
                info["bindip"]+",", str(info["port"])+",", info["ver"]
