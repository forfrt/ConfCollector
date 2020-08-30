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

def merge_ip(conn_list):
    ip_seg = {}
    rex = re.compile(r"\d*\.\d*")
    for conn in conn_list:
        one_ip_seg = rex.search(conn["host"]).group(0)
        ip_seg[one_ip_seg] = True
    ip_seg_list = ""
    for one_ip_seg,flag in ip_seg.items():
        ip_seg_list = ip_seg_list+"|"+one_ip_seg
    return ip_seg_list

with open("./success_log","r") as f: 
    rex = re.compile(r"76102255dfdfb28a5083([^\n]*)")
    flag = False
    for line in f:
        one = rex.search(line)
        if one:
            one = one.group(1).split()
            if len(one) > 1:
                info = json.loads(one[1])
                ip_seg_list = merge_ip(info)
                if ip_seg_list != "":
                    print one[0]+",",
                    print id_ip[one[0]]+","+merge_ip(info)
