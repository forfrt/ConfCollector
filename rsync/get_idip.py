with open("./agent-info.csv", "r") as f1: 
    for line in f1:
        info = line.split(",")
        agent_id = info[0]
        agent_ip = info[1]
        if agent_ip == "0.0.0.0":
            agent_ip = info[2]
        print agent_id,agent_ip 
