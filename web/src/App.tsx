import { useState } from "react";
import TopologyGraph from "./components/TopologyGraph";
import NodeDetail from "./components/NodeDetail";
import "./index.css";

type TopologyData = {
  topo: {
    nodes: any[];
    portlists?: any[];
    links: any[];
  };
};

function App() {
  const [topologyData, setTopologyData] = useState<TopologyData | null>(null);
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [fileName, setFileName] = useState("No file selected");
  const [searchTerm, setSearchTerm] = useState("");
  const [exportSignal, setExportSignal] = useState(0);

  const nodeCount = topologyData?.topo?.nodes?.length ?? "--";
  const linkCount = topologyData?.topo?.links?.length ?? "--";


  const handleJsonUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];

    if (!file) return;

    if (!file.name.toLowerCase().endsWith(".json")) {
      alert("Please upload a .json file.");
      event.target.value = "";
      return;
    }

    const reader = new FileReader();

    reader.onload = (e) => {
      try {
        const text = e.target?.result as string;
        const json = JSON.parse(text);

        if (!isValidTopologyJson(json)) {
          alert("Invalid topology JSON. Required format: topo.nodes and topo.links.");
          event.target.value = "";
          return;
        }

        setTopologyData(json);
        setSelectedNode(null);
        setSearchTerm("");
        setFileName(file.name);

        // Important: allow uploading the same file again
        event.target.value = "";
      } catch (error) {
        alert("Invalid JSON file.");
        console.error(error);
        event.target.value = "";
      }
    };

    reader.readAsText(file);
  };

  const handleExportGraph = () => {
    setExportSignal((prev) => prev + 1);
  };

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand-section">
          <p className="eyebrow">Network Tool</p>
          <h1>Topology Visualizer</h1>
          <p className="subtitle">
            Upload a topology JSON file and visualize the network as an
            interactive graph.
          </p>
        </div>

        <div className="upload-card">
          <p className="card-title">Upload Topology JSON</p>

          <label className="upload-button">
            Choose JSON File
            <input
              type="file"
              accept=".json,application/json"
              onChange={handleJsonUpload}
            />
          </label>

          <p className="file-name">{fileName}</p>
        </div>

        <div className="search-card">
          <p className="card-title">Search Node</p>
          <input
            className="search-input"
            placeholder="Search IP or device name..."
            value={searchTerm}
            onChange={(event) => setSearchTerm(event.target.value)}
          />
        </div>

        <div className="stat-grid">
          <div className="mini-stat">
            <span>Nodes</span>
            <strong>{nodeCount}</strong>
          </div>

          <div className="mini-stat">
            <span>Links</span>
            <strong>{linkCount}</strong>
          </div>
        </div>

        <NodeDetail node={selectedNode} />
      </aside>

      <main className="main-panel">
        <div className="topbar">
          <div>
            <p className="eyebrow">Live Graph</p>
            <h2>Network Map</h2>
          </div>

          <button className="export-button" onClick={handleExportGraph}>
            Export PNG
          </button>
        </div>

        <div className="graph-card">
          <TopologyGraph
            topologyData={topologyData}
            searchTerm={searchTerm}
            exportSignal={exportSignal}
            onNodeSelect={setSelectedNode}
          />
        </div>
      </main>
    </div>
  );
}

function isValidTopologyJson(data: any) {
  return (
    data &&
    data.topo &&
    Array.isArray(data.topo.nodes) &&
    Array.isArray(data.topo.links)
  );
}

export default App;