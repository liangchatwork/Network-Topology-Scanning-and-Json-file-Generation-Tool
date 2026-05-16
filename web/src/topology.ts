export type TopologyNode = {
    device_name: string;
    flag: number;
    gateway: string;
    id: string;
    ip: string;
    ip_on: boolean;
    knmp_on: boolean;
    mac: string;
    netmask: string;
    snmp_on: boolean;
    vlan: number;
  };
  
  export type TopologyLink = {
    source: string;
    source_port_disp: string;
    target: string;
    target_port_disp: string;
  };
  
  export type TopologyData = {
    topo: {
      nodes: TopologyNode[];
      portlists: any[];
      links: TopologyLink[];
    };
  };
  
  const LOCALHOST = "127.0.0.1";
  
  function createNode(ip: string): TopologyNode {
    return {
      device_name: ip === LOCALHOST ? "localhost" : ip,
      flag: 0,
      gateway: "0.0.0.0",
      id: ip,
      ip,
      ip_on: true,
      knmp_on: true,
      mac: "",
      netmask: "255.255.255.0",
      snmp_on: true,
      vlan: 1,
    };
  }
  
  export function parseNmapTracerouteText(text: string): TopologyData {
    const nodeMap = new Map<string, TopologyNode>();
    const linkSet = new Set<string>();
  
    nodeMap.set(LOCALHOST, createNode(LOCALHOST));
  
    const lines = text.split(/\r?\n/);
    let currentRoute: string[] = [];
    let currentTarget = "";
  
    const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
  
    const flushRoute = () => {
      if (currentRoute.length === 0 && currentTarget) {
        currentRoute = [LOCALHOST, currentTarget];
      }
  
      if (currentRoute.length === 1) {
        currentRoute = [LOCALHOST, currentRoute[0]];
      }
  
      for (const ip of currentRoute) {
        if (!nodeMap.has(ip)) {
          nodeMap.set(ip, createNode(ip));
        }
      }
  
      for (let i = 0; i < currentRoute.length - 1; i++) {
        const source = currentRoute[i];
        const target = currentRoute[i + 1];
  
        if (source === target) continue;
  
        const key = `${source}->${target}`;
  
        if (!linkSet.has(key)) {
          linkSet.add(key);
        }
      }
  
      currentRoute = [];
      currentTarget = "";
    };
  
    for (const line of lines) {
      if (line.startsWith("Nmap scan report for")) {
        flushRoute();
  
        const match = line.match(ipRegex);
        currentTarget = match ? match[0] : "";
        continue;
      }
  
      const trimmed = line.trim();
  
      if (/^\d+\s+/.test(trimmed)) {
        const match = trimmed.match(ipRegex);
  
        if (match) {
          currentRoute.push(match[0]);
        }
      }
    }
  
    flushRoute();
  
    const links: TopologyLink[] = Array.from(linkSet).map((key) => {
      const [source, target] = key.split("->");
  
      return {
        source,
        source_port_disp: "",
        target,
        target_port_disp: "",
      };
    });
  
    return {
      topo: {
        nodes: Array.from(nodeMap.values()),
        portlists: [],
        links,
      },
    };
  }
  
  export function downloadTopologyJson(data: TopologyData) {
    const jsonText = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonText], { type: "application/json" });
    const url = URL.createObjectURL(blob);
  
    const link = document.createElement("a");
    link.href = url;
    link.download = "generated_topology.json";
    link.click();
  
    URL.revokeObjectURL(url);
  }