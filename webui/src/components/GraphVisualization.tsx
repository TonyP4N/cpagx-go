import React, { useEffect, useRef, useState } from 'react';
import dynamic from 'next/dynamic';

// Dynamically import CytoscapeComponent to avoid SSR issues
const CytoscapeComponent = dynamic(() => import('react-cytoscapejs'), {
  ssr: false,
  loading: () => <div className="h-96 bg-gray-100 animate-pulse rounded-lg" />
});

interface Node {
  id: string;
  task_id: string;
  node_type: string;
  properties: Record<string, any>;
}

interface Edge {
  source: string;
  target: string;
  task_id: string;
  edge_type: string;
  properties: Record<string, any>;
}

interface GraphData {
  nodes: Node[];
  edges: Edge[];
}

interface GraphVisualizationProps {
  taskId: string;
  onNodeSelect?: (nodeId: string, nodeData: Node) => void;
  onEdgeSelect?: (edgeId: string, edgeData: Edge) => void;
}

const GraphVisualization: React.FC<GraphVisualizationProps> = ({
  taskId,
  onNodeSelect,
  onEdgeSelect
}) => {
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedElement, setSelectedElement] = useState<any>(null);
  const cyRef = useRef<any>(null);

  // Fetch graph data
  useEffect(() => {
    if (!taskId) return;

    const fetchGraphData = async () => {
      try {
        setLoading(true);
        setError(null);
        
        const response = await fetch(`/api/graph/data/${taskId}`);
        if (!response.ok) {
          throw new Error(`Failed to fetch graph data: ${response.statusText}`);
        }
        
        const data = await response.json();
        setGraphData(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Unknown error');
      } finally {
        setLoading(false);
      }
    };

    fetchGraphData();
  }, [taskId]);

  // Transform data for Cytoscape
  const cytoscapeElements = React.useMemo(() => {
    if (!graphData) return [];

    const nodes = graphData.nodes.map(node => ({
      data: {
        id: node.id,
        label: node.properties?.label || node.id,
        nodeType: node.node_type,
        ...node.properties
      },
      classes: `node-${node.node_type}`
    }));

    const edges = graphData.edges.map((edge, index) => ({
      data: {
        id: `edge-${index}`,
        source: edge.source,
        target: edge.target,
        label: edge.edge_type,
        edgeType: edge.edge_type,
        ...edge.properties
      },
      classes: `edge-${edge.edge_type}`
    }));

    return [...nodes, ...edges];
  }, [graphData]);

  // Cytoscape layout and style
  const layout = {
    name: 'grid',
    rows: 2,
    cols: 2,
    position: function(node: any) {
      return node;
    },
    padding: 50
  };

  const stylesheet = [
    {
      selector: 'node',
      style: {
        'background-color': '#3B82F6',
        'label': 'data(label)',
        'text-valign': 'center',
        'text-halign': 'center',
        'color': '#1F2937',
        'text-outline-color': '#FFFFFF',
        'text-outline-width': 2,
        'font-size': '12px',
        'width': '30px',
        'height': '30px'
      }
    },
    {
      selector: 'node:selected',
      style: {
        'background-color': '#EF4444',
        'border-width': 3,
        'border-color': '#DC2626'
      }
    },
    {
      selector: 'edge',
      style: {
        'width': 2,
        'line-color': '#6B7280',
        'target-arrow-color': '#6B7280',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'label': 'data(label)',
        'font-size': '10px',
        'text-rotation': 'autorotate',
        'color': '#374151'
      }
    },
    {
      selector: 'edge:selected',
      style: {
        'line-color': '#EF4444',
        'target-arrow-color': '#EF4444',
        'width': 3
      }
    },
    // Node type specific styles
    {
      selector: '.node-device',
      style: {
        'background-color': '#10B981',
        'shape': 'rectangle'
      }
    },
    {
      selector: '.node-vulnerability',
      style: {
        'background-color': '#F59E0B',
        'shape': 'triangle'
      }
    },
    {
      selector: '.node-attack',
      style: {
        'background-color': '#EF4444',
        'shape': 'diamond'
      }
    },
    // Edge type specific styles
    {
      selector: '.edge-exploits',
      style: {
        'line-color': '#EF4444',
        'target-arrow-color': '#EF4444'
      }
    },
    {
      selector: '.edge-connects',
      style: {
        'line-color': '#3B82F6',
        'target-arrow-color': '#3B82F6'
      }
    }
  ];

  // Handle element selection
  const handleCyReady = (cy: any) => {
    cyRef.current = cy;

    cy.on('select', 'node', (event: any) => {
      const node = event.target;
      const nodeData = graphData?.nodes.find(n => n.id === node.id());
      if (nodeData && onNodeSelect) {
        onNodeSelect(node.id(), nodeData);
      }
      setSelectedElement({ type: 'node', data: node.data() });
    });

    cy.on('select', 'edge', (event: any) => {
      const edge = event.target;
      const edgeData = graphData?.edges.find(e => 
        e.source === edge.data('source') && e.target === edge.data('target')
      );
      if (edgeData && onEdgeSelect) {
        onEdgeSelect(edge.id(), edgeData);
      }
      setSelectedElement({ type: 'edge', data: edge.data() });
    });

    cy.on('unselect', () => {
      setSelectedElement(null);
    });
  };

  // Control functions
  const fitGraph = () => {
    if (cyRef.current) {
      cyRef.current.fit();
    }
  };

  const centerGraph = () => {
    if (cyRef.current) {
      cyRef.current.center();
    }
  };

  const exportImage = () => {
    if (cyRef.current) {
      const png = cyRef.current.png({
        output: 'blob',
        bg: 'white',
        full: true,
        scale: 2
      });
      
      const url = URL.createObjectURL(png);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cpag-graph-${taskId}.png`;
      a.click();
      URL.revokeObjectURL(url);
    }
  };

  if (loading) {
    return (
      <div className="h-96 bg-gray-100 animate-pulse rounded-lg flex items-center justify-center">
        <div className="text-gray-500">Loading graph visualization...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="h-96 bg-red-50 rounded-lg flex items-center justify-center">
        <div className="text-red-600">Error: {error}</div>
      </div>
    );
  }

  if (!graphData || (graphData.nodes.length === 0 && graphData.edges.length === 0)) {
    return (
      <div className="h-96 bg-gray-50 rounded-lg flex items-center justify-center">
        <div className="text-gray-500">No graph data available</div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Controls */}
      <div className="flex justify-between items-center">
        <div className="flex space-x-2">
          <button
            onClick={fitGraph}
            className="px-3 py-1 bg-blue-500 text-white rounded hover:bg-blue-600 text-sm"
          >
            Fit
          </button>
          <button
            onClick={centerGraph}
            className="px-3 py-1 bg-green-500 text-white rounded hover:bg-green-600 text-sm"
          >
            Center
          </button>
          <button
            onClick={exportImage}
            className="px-3 py-1 bg-purple-500 text-white rounded hover:bg-purple-600 text-sm"
          >
            Export PNG
          </button>
        </div>
        <div className="text-sm text-gray-600">
          {graphData.nodes.length} nodes, {graphData.edges.length} edges
        </div>
      </div>

      {/* Graph Container */}
      <div className="relative">
        <div className="h-96 border border-gray-300 rounded-lg overflow-hidden">
          <CytoscapeComponent
            elements={cytoscapeElements}
            layout={layout}
            stylesheet={stylesheet}
            style={{ width: '100%', height: '100%' }}
            cy={handleCyReady}
            wheelSensitivity={0.2}
            minZoom={0.1}
            maxZoom={3}
          />
        </div>

        {/* Element Info Panel */}
        {selectedElement && (
          <div className="absolute top-2 right-2 bg-white border border-gray-300 rounded-lg p-3 shadow-lg max-w-xs">
            <h4 className="font-semibold text-sm mb-2">
              {selectedElement.type === 'node' ? 'Node' : 'Edge'} Details
            </h4>
            <div className="text-xs space-y-1">
              <div><strong>ID:</strong> {selectedElement.data.id}</div>
              <div><strong>Type:</strong> {selectedElement.data.nodeType || selectedElement.data.edgeType}</div>
              {selectedElement.data.label && (
                <div><strong>Label:</strong> {selectedElement.data.label}</div>
              )}
              {selectedElement.type === 'edge' && (
                <>
                  <div><strong>Source:</strong> {selectedElement.data.source}</div>
                  <div><strong>Target:</strong> {selectedElement.data.target}</div>
                </>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="bg-gray-50 p-3 rounded-lg">
        <h4 className="font-semibold text-sm mb-2">Legend</h4>
        <div className="grid grid-cols-2 gap-2 text-xs">
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-green-500 rounded"></div>
            <span>Device</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-yellow-500" style={{ clipPath: 'polygon(50% 0%, 0% 100%, 100% 100%)' }}></div>
            <span>Vulnerability</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-red-500 transform rotate-45"></div>
            <span>Attack</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-0.5 bg-blue-500"></div>
            <span>Connection</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default GraphVisualization;