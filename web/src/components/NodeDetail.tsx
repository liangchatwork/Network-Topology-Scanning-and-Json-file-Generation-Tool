type NodeDetailProps = {
    node: any | null;
  };
  
  function NodeDetail({ node }: NodeDetailProps) {
    if (!node) {
      return (
        <div className="node-detail empty">
          <p className="card-title">Node Detail</p>
          <p className="muted">Click a node to inspect device information.</p>
        </div>
      );
    }
  
    return (
      <div className="node-detail">
        <p className="card-title">Node Detail</p>
  
        <div className="detail-row">
          <span>Device</span>
          <strong>{node.device_name || "Unknown"}</strong>
        </div>
  
        <div className="detail-row">
          <span>IP Address</span>
          <strong>{node.ip || "N/A"}</strong>
        </div>
  
        <div className="detail-row">
          <span>Netmask</span>
          <strong>{node.netmask || "N/A"}</strong>
        </div>
  
        <div className="detail-row">
          <span>Gateway</span>
          <strong>{node.gateway || "N/A"}</strong>
        </div>
  
        <div className="detail-row">
          <span>VLAN</span>
          <strong>{node.vlan ?? "N/A"}</strong>
        </div>
  
        <div className="detail-row">
          <span>SNMP</span>
          <strong className={node.snmp_on ? "status-on" : "status-off"}>
            {node.snmp_on ? "Enabled" : "Disabled"}
          </strong>
        </div>
  
        <div className="detail-row">
          <span>MAC</span>
          <strong>{node.mac || "N/A"}</strong>
        </div>
      </div>
    );
  }
  
  export default NodeDetail;