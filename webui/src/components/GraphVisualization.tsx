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
  label?: string;
  type?: string;
  name?: string;
  category?: string;
  count?: number;
  service?: string;
  dst?: string;
  path?: string;
}

interface Edge {
  source: string;
  target: string;
  task_id: string;
  edge_type: string;
  properties: Record<string, any>;
  relation?: string;
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
        console.log(`GraphVisualization: Fetching data for task ${taskId}`);
        
        const response = await fetch(`/api/graph/data/${taskId}`);
        if (!response.ok) {
          throw new Error(`Failed to fetch graph data: ${response.statusText}`);
        }
        
        const data = await response.json();
        // Ensure edges is always an array
        if (!data.edges) {
          data.edges = [];
        }
        console.log(`GraphVisualization: Received data with ${data.nodes?.length || 0} nodes and ${data.edges?.length || 0} edges`);
        setGraphData(data);
      } catch (err) {
        console.error('GraphVisualization: Error fetching data:', err);
        setError(err instanceof Error ? err.message : 'Unknown error');
      } finally {
        setLoading(false);
      }
    };

    fetchGraphData();
  }, [taskId]);

  // Transform data for Cytoscape with error handling
  const cytoscapeElements = React.useMemo(() => {
    if (!graphData) return [];

    try {
      // Validate and transform nodes with flexible property handling
      const nodes = (graphData.nodes || [])
        .filter(node => node && node.id) // Filter out invalid nodes
        .map(node => {
          try {
            // Handle both v1 and v2 node formats
            const nodeData = {
              id: String(node.id),
              label: node.label || node.properties?.label || node.properties?.service || node.name || node.id,
              nodeType: node.type || node.node_type || 'unknown',
              taskId: node.task_id || '',
              category: node.category || node.properties?.category || 'unknown',
              count: node.count || node.properties?.count || 0,
              service: node.service || node.properties?.service || '',
              // Include all properties for backward compatibility
              ...(node.properties || {}),
              // Include direct fields for v2 compatibility
              dst: node.dst || '',
              path: node.path || ''
            };

            return {
              data: nodeData,
              classes: `node-${nodeData.nodeType}`
            };
          } catch (err) {
            console.warn('Error processing node:', node, err);
            return null;
          }
        })
        .filter((node): node is NonNullable<typeof node> => node !== null); // Remove null entries

      // Validate and transform edges with flexible property handling
      const edges = (graphData.edges || [])
        .filter(edge => edge && edge.source && edge.target) // Filter out invalid edges
        .map((edge, index) => {
          try {
            // Handle both v1 and v2 edge formats
            const edgeData = {
              id: `edge-${edge.source}-${edge.target}-${index}`,
              source: String(edge.source),
              target: String(edge.target),
              label: edge.relation || edge.edge_type || 'connects',
              edgeType: edge.relation || edge.edge_type || 'unknown',
              taskId: edge.task_id || '',
              // Include all properties for backward compatibility
              ...(edge.properties || {})
            };

            return {
              data: edgeData,
              classes: `edge-${edgeData.edgeType}`
            };
          } catch (err) {
            console.warn('Error processing edge:', edge, err);
            return null;
          }
        })
        .filter((edge): edge is NonNullable<typeof edge> => edge !== null); // Remove null entries

      console.log(`Processed ${nodes.length} nodes and ${edges.length} edges`);
      return [...nodes, ...edges];
    } catch (err) {
      console.error('Error transforming graph data:', err);
      setError(`Error processing graph data: ${err instanceof Error ? err.message : 'Unknown error'}`);
      return [];
    }
  }, [graphData]);

  // Cytoscape layout and style - use better layout for large graphs
  const layout = React.useMemo(() => {
    const nodeCount = graphData?.nodes?.length || 0;
    const edgeCount = graphData?.edges?.length || 0;
    console.log(`GraphVisualization: Rendering ${nodeCount} nodes and ${edgeCount} edges`);
    
    if (nodeCount === 0) {
      return { name: 'grid', fit: true };
    }
    
    if (nodeCount > 100) {
      // For very large graphs, use simple circle layout
      console.log('Using circle layout for very large graph');
      return {
        name: 'circle',
        radius: Math.max(200, nodeCount * 3),
        padding: 30,
        fit: true
      };
    } else if (nodeCount > 50) {
      // For large graphs, use optimized force-directed layout
      console.log('Using optimized cose layout for large graph');
      return {
        name: 'cose',
        idealEdgeLength: 80,
        nodeOverlap: 10,
        refresh: 10,
        fit: true,
        padding: 20,
        randomize: false,
        componentSpacing: 50,
        nodeRepulsion: 200000,
        edgeElasticity: 50,
        nestingFactor: 3,
        gravity: 40,
        numIter: 500,  // Reduced iterations for performance
        initialTemp: 100,
        coolingFactor: 0.98,
        minTemp: 2.0
      };
    } else if (nodeCount > 20) {
      // For medium graphs, use circle layout
      console.log('Using circle layout for medium graph');
      return {
        name: 'circle',
        radius: Math.max(150, nodeCount * 5),
        padding: 50,
        fit: true
      };
    } else {
      // For small graphs, use grid layout
      console.log('Using grid layout for small graph');
      return {
        name: 'grid',
        rows: Math.ceil(Math.sqrt(nodeCount)),
        cols: Math.ceil(Math.sqrt(nodeCount)),
        padding: 50,
        fit: true
      };
    }
  }, [graphData?.nodes?.length, graphData?.edges?.length]);

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
        'width': '40px',
        'height': '40px'
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
      selector: '.node-action',
      style: {
        'background-color': '#3B82F6',
        'shape': 'ellipse',
        'width': '50px',
        'height': '35px'
      }
    },
    {
      selector: '.node-device',
      style: {
        'background-color': '#10B981',
        'shape': 'rectangle',
        'width': '45px',
        'height': '45px'
      }
    },
    {
      selector: '.node-vulnerability',
      style: {
        'background-color': '#F59E0B',
        'shape': 'triangle',
        'width': '40px',
        'height': '40px'
      }
    },
    {
      selector: '.node-attack',
      style: {
        'background-color': '#EF4444',
        'shape': 'diamond',
        'width': '40px',
        'height': '40px'
      }
    },
    {
      selector: '.node-unknown',
      style: {
        'background-color': '#6B7280',
        'shape': 'octagon',
        'width': '35px',
        'height': '35px'
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

  if (!graphData || (graphData.nodes?.length === 0 && (graphData.edges?.length || 0) === 0)) {
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
          {graphData?.nodes?.length || 0} nodes, {graphData?.edges?.length || 0} edges
        </div>
      </div>

      {/* Graph Container */}
      <div className="relative">
        <div className="h-96 border border-gray-300 rounded-lg overflow-hidden">
          {cytoscapeElements.length === 0 ? (
            <div className="h-full flex items-center justify-center text-gray-500">
              No graph elements to display
            </div>
          ) : (
            <div className="h-full">
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
          )}
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
        <div className="grid grid-cols-3 gap-2 text-xs">
          <div className="flex items-center space-x-2">
            <div className="w-4 h-3 bg-blue-500 rounded-full"></div>
            <span>Action</span>
          </div>
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
            <div className="w-3 h-3 bg-gray-500" style={{ clipPath: 'polygon(30% 0%, 70% 0%, 100% 30%, 100% 70%, 70% 100%, 30% 100%, 0% 70%, 0% 30%)' }}></div>
            <span>Unknown</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-0.5 bg-gray-600"></div>
            <span>Connection</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default GraphVisualization;