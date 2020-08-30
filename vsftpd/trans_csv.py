import json
import re

id_ip = {}
with open("./id_list_all","r") as f:
    for line in f:
        info = line.split()
        id_ip[info[0]] = info[1]
#print id_ip

with open("./success_log","r") as f: 
    rex = re.compile(r"76102255dfdfb28a5083([^\n]*)")
    flag = False
    for line in f:
        one = rex.search(line)
        if one:
            one = one.group(1).split()
            while len(one) != 2:
                one[1] = one[1]+" "+one[2]
                del one[2]
            info = json.loads(one[1])
            info = info[0]
            print one[0]+",",id_ip[one[0]],",",
            print info["user"]+",", info["uid"]+",", info["gid"]+",", info["conf_file"]+",",\
                info["port"]+",", info["version"]+",", 
            conf = info["config"]
            print conf["anonymous_enable"]+",", conf["anon_upload_enable"]+",",\
                conf["anon_mkdir_write_enable"],",",conf["anon_other_write_enable"],",",\
                conf["local_enable"],",",conf["write_enable"],",",\
                conf["local_umask"],",",conf["chroot_local_user"],",",\
                conf["userlist_enable"],",",conf["userlist_deny"],",",\
                conf["userlist_file"],",",conf["userlist"],",",\
                conf["xferlog_enable"]
