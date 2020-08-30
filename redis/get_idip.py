import json

with open("./ip_list_json", "r") as f:
    content = f.read()
    info = json.loads(content)
    ip_list = {}
    for row in info["data"]["rows"]:
        if row["internal_ip"] == "0.0.0.0":
            ip_list[row["external_ip"]] = 1
        else:
            if ip_list.has_key(row["internal_ip"]):
                pass
                #print row["internal_ip"]
            else:
                ip_list[row["internal_ip"]] = 1
    with open("./agent-info.csv", "r") as f1: 
        for line in f1:
            info = line.split(",")
            agent_id = info[0]
            agent_ip = info[1]
            if agent_ip == "0.0.0.0":
                agent_ip = info[2]
            if ip_list.has_key(agent_ip):
                ip_list[agent_ip] += 1
                print agent_id,agent_ip 
    """no agent id or same internal_ip but different agent id
    for k,v in ip_list.items():
        if v != 2:
            print k
    """
