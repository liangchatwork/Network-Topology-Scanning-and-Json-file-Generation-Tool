import json
import re
import sys

def nodes_gen(topo_filename):
    
    nodes = []
    ip = {}

    nodes.append(
        {
            "device_name": "localhost",
            "flag": 0,
            "gateway": "0.0.0.0",
            "id": "127.0.0.1",
            "ip": "127.0.0.1",
            "ip_on": True,
            "knmp_on": True,
            "mac": "",
            "netmask": "255.255.255.0",
            "snmp_on": True,
            "vlan": 1
        }
    )

    with open(topo_filename, 'r') as file:
        lines = file.readlines()

    for line in lines:
        if line.startswith("Nmap scan report for"):
            pattern = re.compile(r"Nmap scan report for\s+([\w\.-]+)\s+\((\d{1,3}(?:\.\d{1,3}){3})\)|Nmap scan report for\s+(\d{1,3}(?:\.\d{1,3}){3})")
            match = pattern.findall(line)
            if match and match[0][0] != "" and match[0][1] != "":
                nodes.append(
                    {
                        "device_name": match[0][0],
                        "flag": 0,
                        "gateway": "0.0.0.0",
                        "id": match[0][1],
                        "ip": match[0][1],
                        "ip_on": True,
                        "knmp_on": True,
                        "mac": "",
                        "netmask": "255.255.255.0",
                        "snmp_on": True,
                        "vlan": 1
                    }
                )
                ip[match[0][1]] = []
            elif match and match[0][2] != "":
                nodes.append(
                    {
                        "device_name": match[0][2],
                        "flag": 0,
                        "gateway": "0.0.0.0",
                        "id": match[0][2],
                        "ip": match[0][2],
                        "ip_on": True,
                        "knmp_on": True,
                        "mac": "",
                        "netmask": "255.255.255.0",
                        "snmp_on": True,
                        "vlan": 1
                    }
                )
                ip[match[0][2]] = []

    # print(json.dumps(nodes, indent=4))
    return nodes, ip


def modify_txt(topo_filename):
    
    with open(topo_filename, 'r') as file:
        lines = file.readlines()


    with open("topo_processed.txt", 'w') as f:
        for line in lines:
            ip_match = re.match(r"Nmap scan report for (.+?) \((\d+\.\d+\.\d+\.\d+)\)", line)
            if ip_match:
                ip = ip_match.group(2)
                line = f"Nmap scan report for {ip}\n"
            if line.startswith("Host is up") or line.startswith("TRACEROUTE") or line.startswith("HOP"):
                continue
            f.write(line)

    return


def add_nodes_gen(nodes, ipdic):
    
    pattern = re.compile(r"(\d+)\s+(\d+\.\d{2})\s+ms\s+([\w\.-]+)\s+\((\d{1,3}(?:\.\d{1,3}){3})\)|(\d+)\s+(\d+\.\d{2})\s+ms\s+(\d{1,3}(?:\.\d{1,3}){3})|(\d+)\s+--\s+([\w\.-]+)\s+\((\d{1,3}(?:\.\d{1,3}){3})\)|(\d+)\s+--\s+(\d{1,3}(?:\.\d{1,3}){3})|-\s+Hops\s+(\d+)-(\d+)\s+are\s+the\s+same\s+as\s+for\s+(\d{1,3}(?:\.\d{1,3}){3})|-\s+Hop\s+(\d+)\s+is\s+the\s+same\s+as\s+for\s+(\d{1,3}(?:\.\d{1,3}){3})|(\d+)\s+\.\.\.\s+(\d+)")

    with open("topo_processed.txt", 'r') as file:
        lines = file.readlines()
        for line in lines:
            if line.startswith("Nmap scan report for"):
                ip = line.split()[-1]
                continue
            
            match = pattern.findall(line)
            if match and match[0][0] != "" and match[0][1] != "" and match[0][2] != "" and match[0][3] != "":
                nodes.append(
                    {
                        "device_name": match[0][2],
                        "flag": 0,
                        "gateway": "0.0.0.0",
                        "id": match[0][3],
                        "ip": match[0][3],
                        "ip_on": True,
                        "knmp_on": True,
                        "mac": "",
                        "netmask": "255.255.255.0",
                        "snmp_on": True,
                        "vlan": 1
                    }
                )
                ipdic[ip].append(match[0][3])
            elif match and match[0][4]!= "" and match[0][5]!= "" and match[0][6]!= "":
                nodes.append(
                    {
                        "device_name": match[0][6],
                        "flag": 0,
                        "gateway": "0.0.0.0",
                        "id": match[0][6],
                        "ip": match[0][6],
                        "ip_on": True,
                        "knmp_on": True,
                        "mac": "",
                        "netmask": "255.255.255.0",
                        "snmp_on": True,
                        "vlan": 1
                    }
                )
                ipdic[ip].append(match[0][6])
            elif match and match[0][7]!= "" and match[0][8]!= "" and match[0][9]!= "":
                nodes.append(
                    {
                        "device_name": match[0][8],
                        "flag": 0,
                        "gateway": "0.0.0.0",
                        "id": match[0][9],
                        "ip": match[0][9],
                        "ip_on": True,
                        "knmp_on": True,
                        "mac": "",
                        "netmask": "255.255.255.0",
                        "snmp_on": True,
                        "vlan": 1
                    }
                )
                ipdic[ip].append(match[0][9])
            elif match and match[0][10]!= "" and match[0][11]!= "":
                nodes.append(
                    {
                        "device_name": match[0][11],
                        "flag": 0,
                        "gateway": "0.0.0.0",
                        "id": match[0][11],
                        "ip": match[0][11],
                        "ip_on": True,
                        "knmp_on": True,
                        "mac": "",
                        "netmask": "255.255.255.0",
                        "snmp_on": True,
                        "vlan": 1
                    }
                )
                ipdic[ip].append(match[0][11])
            elif match and match[0][12]!= "" and match[0][13]!= "" and match[0][14]!= "":
                ipdic[ip]+=ipdic[match[0][14]][int(match[0][12])-1:int(match[0][13])]
            elif match and match[0][15]!= "" and match[0][16]!= "":
                ipdic[ip]+=ipdic[match[0][16]][int(match[0][15])-1:int(match[0][15])]
            
    nodes_combined_tuples = [tuple(sorted(d.items())) for d in nodes]
    nodes = [dict(t) for t in set(nodes_combined_tuples)]
    # print(json.dumps(nodes, indent=4))
    # print(len(nodes))
    # print(json.dumps(ipdic, indent=4))
    return nodes, ipdic


def links_gen(ipdic):
    
    links = []
    for ip in ipdic:
        prev_ip = "127.0.0.1"
        for hop in ipdic[ip]:
            if prev_ip != hop:
                links.append(
                    {
                        "source": prev_ip,
                        "source_port_disp": "",
                        "target": hop,
                        "target_port_disp": ""
                    }
                )
            prev_ip = hop
    
    links_combined_tuples = [tuple(sorted(d.items())) for d in links]
    links = [dict(t) for t in set(links_combined_tuples)]
    print(json.dumps(links, indent=4))
    return links



if __name__ == '__main__':

    topo_filename = sys.argv[1]
    
    # Step 1 : Nodes Generation
    nodes, ipdic = nodes_gen(topo_filename)

    # Step 2 : Modify new Topo txt file
    modify_txt(topo_filename) 

    # Step 3 : Additional Nodes Generation
    nodes, ipdic = add_nodes_gen(nodes, ipdic)

    # Step 4 : Links Generation
    links = links_gen(ipdic)

    # Step 5 : Topo Generation
    data = {
        "topo":{
            "nodes": nodes,
            "portlists" : [],
            "links": links
        }
    }

    output_filename = sys.argv[1][:-4]
    with open(output_filename+'.json', 'w') as f:
        json.dump(data, f, indent=4)
