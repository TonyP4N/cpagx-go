import React, { useEffect, useRef, useState } from 'react';
import dynamic from 'next/dynamic';
import cytoscape from 'cytoscape';

// Import layout extensions
import dagre from 'cytoscape-dagre';
import cola from 'cytoscape-cola';
import coseBilkent from 'cytoscape-cose-bilkent';

// Register the layout extensions with Cytoscape
if (typeof cytoscape !== 'undefined') {
  cytoscape.use(dagre);
  cytoscape.use(cola);
  cytoscape.use(coseBilkent);
}

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
  logic_type?: string;
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
              nodeType: node.type || node.node_type || node.properties?.type || 'unknown',
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

            // Add both nodeType and category as classes for styling flexibility
            const classes = [`node-${nodeData.nodeType}`];
            if (nodeData.category && nodeData.category !== 'unknown') {
              classes.push(`node-${nodeData.category}`);
            }
            
            return {
              data: nodeData,
              classes: classes.join(' ')
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
              logicType: edge.logic_type || 'SEQUENTIAL',
              taskId: edge.task_id || '',
              // Include all properties for backward compatibility
              ...(edge.properties || {})
            };

            return {
              data: edgeData,
              classes: `edge-${edgeData.edgeType} ${edgeData.logicType ? `logic-${edgeData.logicType.toLowerCase()}` : ''}`
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

  // Cytoscape layout optimized for tree-like CPAG structures
  const layout = React.useMemo(() => {
    const nodeCount = graphData?.nodes?.length || 0;
    const edgeCount = graphData?.edges?.length || 0;
    console.log(`GraphVisualization: Rendering ${nodeCount} nodes and ${edgeCount} edges`);
    
    if (nodeCount === 0) {
      return { name: 'grid', fit: true };
    }
    
    // Check if this looks like a tree-like structure (edges ≈ nodes - 1)
    const isTreeLike = edgeCount > 0 && (edgeCount / nodeCount) < 1.5;
    
    try {
      if (isTreeLike && nodeCount > 8) {
        // For tree-like structures, use dagre (hierarchical) layout
        console.log('Using dagre layout for tree-like CPAG structure');
        return {
          name: 'dagre',
          rankDir: 'TB', // Top to bottom
          align: 'UL', // Align nodes to upper left
          rankSep: 80,
          nodeSep: 40,
          edgeSep: 10,
          padding: 30,
          fit: true,
          animate: false
        };
      } else if (nodeCount > 100) {
        // For very large graphs, use cola for better performance
        console.log('Using cola layout for very large graph');
        return {
          name: 'cola',
          maxSimulationTime: 2000,
          ungrabifyWhileSimulating: true,
          fit: true,
          padding: 30,
          nodeSpacing: 30,
          flow: { axis: 'y', minSeparation: 30 },
          animate: false
        };
      } else if (nodeCount > 50) {
        // For large graphs, use cose-bilkent for better clustering
        console.log('Using cose-bilkent layout for large graph');
        return {
          name: 'cose-bilkent',
          idealEdgeLength: 100,
          nodeOverlap: 20,
          refresh: 20,
          fit: true,
          padding: 30,
          randomize: false,
          componentSpacing: 100,
          nodeRepulsion: 4500,
          edgeElasticity: 0.45,
          nestingFactor: 0.1,
          gravity: 0.25,
          numIter: 2500,
          initialTemp: 200,
          coolingFactor: 0.95,
          minTemp: 1.0,
          animate: false
        };
      } else if (nodeCount > 15) {
        // For medium graphs with complex relationships, use dagre for hierarchical layout
        console.log('Using dagre layout for medium hierarchical graph');
        return {
          name: 'dagre',
          rankDir: 'TB', // Top to bottom layout
          padding: 20,
          spacingFactor: 1.25,
          rankSep: 100,
          nodeSep: 50,
          fit: true,
          animate: false
        };
      } else if (nodeCount > 5) {
        // For small-medium graphs, use breadthfirst for clear hierarchy
        console.log('Using breadthfirst layout for small-medium graph');
        return {
          name: 'breadthfirst',
          directed: true,
          padding: 30,
          spacingFactor: 1.5,
          maximal: false,
          grid: false,
          fit: true,
          roots: '#[indegree = 0]', // Start from nodes with no incoming edges
          animate: false
        };
      } else {
        // For very small graphs, use circle layout
        console.log('Using circle layout for very small graph');
        return {
          name: 'circle',
          radius: Math.max(120, nodeCount * 15),
          padding: 50,
          fit: true,
          animate: false
        };
      }
    } catch (error) {
      console.error('Error selecting layout, falling back to cose:', error);
      // Fallback to basic cose layout if any layout fails
      return {
        name: 'cose',
        fit: true,
        padding: 30,
        animate: false
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
    // Node type specific styles - V2 actual types
    {
      selector: '.node-mitm_indicator',
      style: {
        'background-color': '#EF4444',
        'shape': 'diamond',
        'width': '45px',
        'height': '45px'
      }
    },
    {
      selector: '.node-dos_attack',
      style: {
        'background-color': '#DC2626',
        'shape': 'star',
        'width': '50px',
        'height': '50px'
      }
    },
    {
      selector: '.node-protocol_manipulation',
      style: {
        'background-color': '#F59E0B',
        'shape': 'triangle',
        'width': '45px',
        'height': '45px'
      }
    },
    {
      selector: '.node-systematic_enumeration',
      style: {
        'background-color': '#3B82F6',
        'shape': 'rectangle',
        'width': '45px',
        'height': '45px'
      }
    },
    {
      selector: '.node-timing_anomaly',
      style: {
        'background-color': '#8B5CF6',
        'shape': 'ellipse',
        'width': '50px',
        'height': '35px'
      }
    },
    // Category-based styles as fallback
    {
      selector: '.node-attack_execution',
      style: {
        'background-color': '#EF4444',
        'shape': 'diamond',
        'width': '40px',
        'height': '40px'
      }
    },
    {
      selector: '.node-attack_impact',
      style: {
        'background-color': '#DC2626',
        'shape': 'star',
        'width': '45px',
        'height': '45px'
      }
    },
    {
      selector: '.node-reconnaissance',
      style: {
        'background-color': '#3B82F6',
        'shape': 'rectangle',
        'width': '40px',
        'height': '40px'
      }
    },
    {
      selector: '.node-anomaly_detection',
      style: {
        'background-color': '#8B5CF6',
        'shape': 'octagon',
        'width': '40px',
        'height': '40px'
      }
    },
    // Legacy V1 styles
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
    // Edge type specific styles - V2 actual
    {
      selector: '.edge-ENABLES',
      style: {
        'line-color': '#10B981',
        'target-arrow-color': '#10B981',
        'line-style': 'solid',
        'width': 2
      }
    },
    // Legacy edge styles
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
    },
    {
      selector: '.edge-requires',
      style: {
        'line-color': '#10B981',
        'target-arrow-color': '#10B981',
        'line-style': 'solid'
      }
    },
    {
      selector: '.edge-alternative_to',
      style: {
        'line-color': '#F59E0B',
        'target-arrow-color': '#F59E0B',
        'line-style': 'dashed'
      }
    },
    {
      selector: '.edge-required_by',
      style: {
        'line-color': '#8B5CF6',
        'target-arrow-color': '#8B5CF6',
        'line-style': 'dotted'
      }
    },
    // Logic type specific styles
    {
      selector: '.logic-and',
      style: {
        'width': 3,
        'line-style': 'solid'
      }
    },
    {
      selector: '.logic-or',
      style: {
        'width': 2,
        'line-style': 'dashed'
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
                  {selectedElement.data.logicType && (
                    <div><strong>Logic Type:</strong> 
                      <span className={`ml-1 px-2 py-1 rounded text-xs ${
                        selectedElement.data.logicType === 'AND' ? 'bg-green-100 text-green-800' :
                        selectedElement.data.logicType === 'OR' ? 'bg-yellow-100 text-yellow-800' :
                        'bg-gray-100 text-gray-800'
                      }`}>
                        {selectedElement.data.logicType}
                      </span>
                    </div>
                  )}
                </>
              )}
              {selectedElement.type === 'node' && (
                <>
                  {selectedElement.data.precondition_logic_type && (
                    <div><strong>Precondition Logic:</strong> 
                      <span className={`ml-1 px-2 py-1 rounded text-xs ${
                        selectedElement.data.precondition_logic_type === 'AND' ? 'bg-green-100 text-green-800' :
                        selectedElement.data.precondition_logic_type === 'OR' ? 'bg-yellow-100 text-yellow-800' :
                        'bg-gray-100 text-gray-800'
                      }`}>
                        {selectedElement.data.precondition_logic_type}
                      </span>
                    </div>
                  )}
                  {selectedElement.data.dependency_count && (
                    <div><strong>Dependencies:</strong> {selectedElement.data.dependency_count}</div>
                  )}
                  {selectedElement.data.alternative_count && (
                    <div><strong>Alternatives:</strong> {selectedElement.data.alternative_count}</div>
                  )}
                </>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Enhanced Legend with actual node types */}
      <div className="bg-gray-50 p-3 rounded-lg">
        <h4 className="font-semibold text-sm mb-2">Legend</h4>
        <div className="space-y-3">
          {/* Node Types - V2 Actual */}
          <div>
            <div className="font-medium text-xs mb-1 text-gray-700">Attack Types:</div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-red-500 transform rotate-45"></div>
                <span>MITM Indicator</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-red-700" style={{ clipPath: 'polygon(50% 0%, 61% 35%, 98% 35%, 68% 57%, 79% 91%, 50% 70%, 21% 91%, 32% 57%, 2% 35%, 39% 35%)' }}></div>
                <span>DoS Attack</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-yellow-500" style={{ clipPath: 'polygon(50% 0%, 0% 100%, 100% 100%)' }}></div>
                <span>Protocol Manipulation</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-blue-500 rounded"></div>
                <span>Enumeration</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-4 h-3 bg-purple-500 rounded-full"></div>
                <span>Timing Anomaly</span>
              </div>
            </div>
          </div>
          
          {/* Categories */}
          <div>
            <div className="font-medium text-xs mb-1 text-gray-700">Categories:</div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-red-500"></div>
                <span>Attack Execution</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-red-700"></div>
                <span>Attack Impact</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-blue-500"></div>
                <span>Reconnaissance</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-purple-500"></div>
                <span>Anomaly Detection</span>
              </div>
            </div>
          </div>
          
          {/* Relationship Types */}
          <div>
            <div className="font-medium text-xs mb-1 text-gray-700">Relationship Types:</div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="flex items-center space-x-2">
                <div className="w-4 h-0.5 bg-green-500"></div>
                <span>Enables</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-4 h-0.5 bg-gray-600"></div>
                <span>Sequential Flow</span>
              </div>
            </div>
          </div>
          
          {/* Logic Types */}
          <div>
            <div className="font-medium text-xs mb-1 text-gray-700">Logic Types:</div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="flex items-center space-x-2">
                <div className="w-4 h-0.5 bg-green-600" style={{ height: '3px' }}></div>
                <span>AND Logic (solid, thick)</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-4 h-0.5" style={{ borderTop: '2px dashed #059669', backgroundColor: 'transparent' }}></div>
                <span>OR Logic (dashed)</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default GraphVisualization;