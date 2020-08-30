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
            print one[0]+",",id_ip[one[0]]+",",
            print str(info["uname"])+",", info["console_path"]+",", info["conf_path"]+",",\
                info["user"]+",",info["pwd"]+",", str(info["port"])+",",\
                str(info["product_mode"])+",", info["deserialize_vul"],",",info["version"]+",",
            if len(info["patch"]) > 0:
                print info["patch"][0]
            else:
                print
