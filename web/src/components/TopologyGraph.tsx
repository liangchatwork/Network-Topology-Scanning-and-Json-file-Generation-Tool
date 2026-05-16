import { useEffect, useRef } from "react";
import CytoscapeComponent from "react-cytoscapejs";
import type cytoscape from "cytoscape";

type TopologyData = {
  topo: {
    nodes: any[];
    portlists?: any[];
    links: any[];
  };
};

type TopologyGraphProps = {
  topologyData: TopologyData | null;
  searchTerm: string;
  exportSignal: number;
  onNodeSelect: (node: any | null) => void;
};

function TopologyGraph({
  topologyData,
  searchTerm,
  exportSignal,
  onNodeSelect,
}: TopologyGraphProps) {
  const cyRef = useRef<cytoscape.Core | null>(null);

  useEffect(() => {
    const cy = cyRef.current;

    if (!cy || !topologyData) return;

    const keyword = searchTerm.trim().toLowerCase();

    const nodeElements = topologyData.topo.nodes.map((node) => {
      const label = node.device_name || node.ip || node.id;
      const searchableText = `${node.id ?? ""} ${node.ip ?? ""} ${
        node.device_name ?? ""
      }`.toLowerCase();

      const isMatched =
        keyword.length > 0 && searchableText.includes(keyword);

      return {
        group: "nodes" as const,
        data: {
          ...node,
          id: String(node.id),
          label,
        },
        classes: [
          node.id === "127.0.0.1" ? "root" : "device",
          isMatched ? "matched" : "",
          keyword.length > 0 && !isMatched ? "dimmed" : "",
        ]
          .filter(Boolean)
          .join(" "),
      };
    });

    const validNodeIds = new Set(
      topologyData.topo.nodes.map((node) => String(node.id))
    );

    const edgeElements = topologyData.topo.links
      .filter((link) => {
        return (
          validNodeIds.has(String(link.source)) &&
          validNodeIds.has(String(link.target))
        );
      })
      .map((link, index) => ({
        group: "edges" as const,
        data: {
          id: `edge-${index}-${link.source}-${link.target}`,
          source: String(link.source),
          target: String(link.target),
        },
      }));

    cy.elements().remove();
    cy.add([...nodeElements, ...edgeElements]);

    cy.layout({
      name: "cose",
      animate: true,
      padding: 100,
      nodeRepulsion: 12000,
      idealEdgeLength: 140,
      edgeElasticity: 100,
      gravity: 0.18,
      numIter: 2500,
    } as any).run();

    cy.fit(undefined, 80);
  }, [topologyData, searchTerm]);

  useEffect(() => {
    const cy = cyRef.current;

    if (!cy || exportSignal === 0) return;

    const png64 = cy.png({
      full: true,
      scale: 2,
      bg: "#020617",
    });

    const link = document.createElement("a");
    link.href = png64;
    link.download = "network-topology.png";
    link.click();
  }, [exportSignal]);

  return (
    <CytoscapeComponent
      elements={[]}
      style={{ width: "100%", height: "100%" }}
      cy={(cy) => {
        cyRef.current = cy;

        cy.off("tap", "node");
        cy.off("tap");

        cy.on("tap", "node", (event) => {
          onNodeSelect(event.target.data());
        });

        cy.on("tap", (event) => {
          if (event.target === cy) {
            onNodeSelect(null);
          }
        });
      }}
      stylesheet={[
        {
          selector: "core",
          style: {
            "background-color": "#020617",
          },
        },
        {
            selector: "node",
            style: {
              label: "data(label)",
              width: 42,
              height: 42,
              "background-color": "#38bdf8",
          
              "background-image":
                "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='white' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><rect x='3' y='4' width='18' height='12' rx='2'/><path d='M8 20h8'/><path d='M12 16v4'/></svg>",
              "background-fit": "contain",
              "background-width": "45%",
              "background-height": "45%",
              "background-opacity": 0.95,
          
              "border-width": 3,
              "border-color": "#bae6fd",
              color: "#e5e7eb",
              "font-size": 9,
              "text-valign": "bottom",
              "text-halign": "center",
              "text-margin-y": 8,
              "text-outline-width": 3,
              "text-outline-color": "#020617",
            },
        },
        {
          selector: "node.root",
          style: {
            width: 68,
            height: 68,
            "background-color": "#8b5cf6",
            "border-color": "#ddd6fe",
            "font-size": 13,
            "font-weight": "bold",
          },
        },
        {
          selector: "node.matched",
          style: {
            width: 68,
            height: 68,
            "background-color": "#22c55e",
            "border-color": "#bbf7d0",
            "border-width": 6,
            "font-size": 12,
            "font-weight": "bold",
          },
        },
        {
          selector: "node.dimmed",
          style: {
            opacity: 0.24,
          },
        },
        {
          selector: "edge",
          style: {
            width: 2,
            "line-color": "#475569",
            "curve-style": "bezier",
            opacity: 0.72,
          },
        },
        {
          selector: "node:selected",
          style: {
            "background-color": "#22c55e",
            "border-color": "#bbf7d0",
            "border-width": 5,
          },
        },
        {
          selector: "edge:selected",
          style: {
            width: 4,
            "line-color": "#22c55e",
          },
        },
      ]}
    />
  );
}

export default TopologyGraph;