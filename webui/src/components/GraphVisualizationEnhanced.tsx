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

interface GraphVisualizationEnhancedProps {
  taskId: string;
  onNodeSelect?: (nodeId: string, nodeData: any) => void;
  onEdgeSelect?: (edgeId: string, edgeData: any) => void;
}

const GraphVisualizationEnhanced: React.FC<GraphVisualizationEnhancedProps> = ({
  taskId,
  onNodeSelect,
  onEdgeSelect
}) => {
  const [graphData, setGraphData] = useState<{nodes: any[], edges: any[]} | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedElement, setSelectedElement] = useState<any>(null);
  const [animationEnabled, setAnimationEnabled] = useState(true);
  const [layoutType, setLayoutType] = useState<string>('auto');
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
        if (!data.edges) {
          data.edges = [];
        }
        setGraphData(data);
      } catch (err) {
        console.error('Error fetching data:', err);
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

    try {
      const nodes = (graphData.nodes || [])
        .filter((node: any) => node && node.id)
        .map((node: any) => {
          // Debug: log first node to see data structure
          if (graphData.nodes.indexOf(node) === 0) {
            console.log('Sample node data:', node);
          }
          const nodeData = {
            id: String(node.id),
            label: node.label || node.properties?.label || node.name || node.id,
            nodeType: node.type || node.node_type || node.properties?.type || 'unknown',
            taskId: node.task_id || '',
            category: node.category || node.properties?.category || 'unknown',
            // Extract confidence from properties
            confidence: node.properties?.confidence || 
                       node.properties?.evidence_confidence || 
                       node.confidence || 
                       0.5,
            // Extract evidence count from properties
            evidence_count: node.properties?.evidence_count || 
                           node.properties?.['evidence.count'] ||
                           node.evidence_count || 
                           0,
            // Add properties for visual enhancement
            size: Math.min(100, 30 + (node.properties?.evidence_count || node.properties?.['evidence.count'] || 0) / 10),
            ...(node.properties || {})
          };

          const classes = [`node-${nodeData.nodeType}`];
          if (nodeData.category && nodeData.category !== 'unknown') {
            classes.push(`node-${nodeData.category}`);
          }
          
          // Add confidence-based class
          if (nodeData.confidence > 0.8) {
            classes.push('high-confidence');
          } else if (nodeData.confidence < 0.5) {
            classes.push('low-confidence');
          }
          
          return {
            data: nodeData,
            classes: classes.join(' ')
          };
        })
        .filter((node: any) => node !== null);

      const edges = (graphData.edges || [])
        .filter((edge: any) => edge && edge.source && edge.target)
        .map((edge: any, index: number) => {
          const edgeData = {
            id: `edge-${edge.source}-${edge.target}-${index}`,
            source: String(edge.source),
            target: String(edge.target),
            label: edge.relation || edge.edge_type || 'connects',
            edgeType: edge.relation || edge.edge_type || 'unknown',
            logicType: edge.logic_type || 'SEQUENTIAL',
            taskId: edge.task_id || '',
            strength: edge.properties?.strength || 1,
            ...(edge.properties || {})
          };

          return {
            data: edgeData,
            classes: `edge-${edgeData.edgeType} ${edgeData.logicType ? `logic-${edgeData.logicType.toLowerCase()}` : ''}`
          };
        })
        .filter((edge: any) => edge !== null);

      return [...nodes, ...edges];
    } catch (err) {
      console.error('Error transforming graph data:', err);
      setError(`Error processing graph data: ${err instanceof Error ? err.message : 'Unknown error'}`);
      return [];
    }
  }, [graphData]);

  // Enhanced layout selection
  const layout = React.useMemo(() => {
    const nodeCount = graphData?.nodes?.length || 0;
    const edgeCount = graphData?.edges?.length || 0;
    
    if (layoutType !== 'auto') {
      // Manual layout selection
      const layouts: any = {
        'dagre': {
          name: 'dagre',
          rankDir: 'TB',
          rankSep: 120,
          nodeSep: 80,
          padding: 30,
          animate: animationEnabled,
          animationDuration: 500
        },
        'cola': {
          name: 'cola',
          maxSimulationTime: 2000,
          nodeSpacing: 50,
          flow: { axis: 'y', minSeparation: 40 },
          animate: animationEnabled,
          animationDuration: 500
        },
        'cose-bilkent': {
          name: 'cose-bilkent',
          idealEdgeLength: 120,
          nodeRepulsion: 5000,
          animate: animationEnabled,
          animationDuration: 500
        },
        'circular': {
          name: 'circle',
          radius: Math.max(150, nodeCount * 10),
          animate: animationEnabled,
          animationDuration: 500
        }
      };
      return layouts[layoutType] || layouts.dagre;
    }
    
    // Auto layout selection (similar to original but with animation)
    if (nodeCount === 0) {
      return { name: 'grid', fit: true };
    }
    
    const isTreeLike = edgeCount > 0 && (edgeCount / nodeCount) < 1.5;
    
    if (isTreeLike && nodeCount > 8) {
      return {
        name: 'dagre',
        rankDir: 'TB',
        rankSep: 100,
        nodeSep: 60,
        padding: 30,
        fit: true,
        animate: animationEnabled,
        animationDuration: 500
      };
    } else if (nodeCount > 50) {
      return {
        name: 'cola',
        maxSimulationTime: 3000,
        nodeSpacing: 40,
        fit: true,
        animate: animationEnabled,
        animationDuration: 1000
      };
    } else {
      return {
        name: 'cose-bilkent',
        idealEdgeLength: 100,
        nodeRepulsion: 4500,
        fit: true,
        animate: animationEnabled,
        animationDuration: 800
      };
    }
  }, [graphData?.nodes?.length, graphData?.edges?.length, layoutType, animationEnabled]);

  // Enhanced stylesheet with animations and gradients
  const stylesheet = [
    // Base node style
    {
      selector: 'node',
      style: {
        'background-color': '#3B82F6',
        'background-opacity': 0.9,
        'label': 'data(label)',
        'text-valign': 'center',
        'text-halign': 'center',
        'color': '#1F2937',
        'text-outline-color': '#FFFFFF',
        'text-outline-width': 2,
        'font-size': '12px',
        'width': 'data(size)',
        'height': 'data(size)',
        'border-width': 2,
        'border-color': '#1E40AF',
        'transition-property': 'background-color, width, height, border-width',
        'transition-duration': '0.3s'
      }
    },
    // Hover effect
    {
      selector: 'node:hover',
      style: {
        'width': (ele: any) => ele.data('size') * 1.2,
        'height': (ele: any) => ele.data('size') * 1.2,
        'border-width': 4,
        'z-index': 9999
      }
    },
    {
      selector: 'node:selected',
      style: {
        'background-color': '#EF4444',
        'border-width': 4,
        'border-color': '#DC2626',
        'width': (ele: any) => ele.data('size') * 1.3,
        'height': (ele: any) => ele.data('size') * 1.3,
        'z-index': 10000
      }
    },
    // High confidence nodes - glow effect
    {
      selector: '.high-confidence',
      style: {
        'border-width': 3,
        'border-color': '#10B981',
        'box-shadow': '0 0 15px #10B981'
      }
    },
    // Low confidence nodes - dashed border
    {
      selector: '.low-confidence',
      style: {
        'border-style': 'dashed',
        'opacity': 0.7
      }
    },
    // Attack type nodes with distinct visual styles
    {
      selector: '.node-mitm_indicator',
      style: {
        'background-color': '#EF4444',
        'background-gradient-stop-colors': '#EF4444 #DC2626',
        'background-gradient-stop-positions': '0% 100%',
        'shape': 'diamond',
        'border-color': '#991B1B'
      }
    },
    {
      selector: '.node-dos_attack',
      style: {
        'background-color': '#DC2626',
        'background-gradient-stop-colors': '#DC2626 #991B1B',
        'background-gradient-stop-positions': '0% 100%',
        'shape': 'star',
        'border-color': '#7F1D1D'
      }
    },
    {
      selector: '.node-protocol_manipulation',
      style: {
        'background-color': '#F59E0B',
        'background-gradient-stop-colors': '#F59E0B #D97706',
        'background-gradient-stop-positions': '0% 100%',
        'shape': 'triangle',
        'border-color': '#92400E'
      }
    },
    {
      selector: '.node-systematic_enumeration',
      style: {
        'background-color': '#3B82F6',
        'background-gradient-stop-colors': '#3B82F6 #2563EB',
        'background-gradient-stop-positions': '0% 100%',
        'shape': 'rectangle',
        'border-color': '#1E40AF'
      }
    },
    {
      selector: '.node-timing_anomaly',
      style: {
        'background-color': '#8B5CF6',
        'background-gradient-stop-colors': '#8B5CF6 #7C3AED',
        'background-gradient-stop-positions': '0% 100%',
        'shape': 'ellipse',
        'border-color': '#5B21B6'
      }
    },
    // Category-based styles
    {
      selector: '.node-attack_execution',
      style: {
        'background-color': '#EF4444',
        'background-gradient-stop-colors': '#EF4444 #DC2626',
        'background-gradient-stop-positions': '0% 100%',
        'shape': 'diamond'
      }
    },
    {
      selector: '.node-reconnaissance',
      style: {
        'background-color': '#3B82F6',
        'background-gradient-stop-colors': '#3B82F6 #2563EB',
        'background-gradient-stop-positions': '0% 100%',
        'shape': 'rectangle'
      }
    },
    // Edge styles with animations
    {
      selector: 'edge',
      style: {
        'width': (ele: any) => Math.max(2, ele.data('strength') * 3),
        'line-color': '#6B7280',
        'target-arrow-color': '#6B7280',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'label': 'data(label)',
        'font-size': '10px',
        'text-rotation': 'autorotate',
        'color': '#374151',
        'text-background-color': '#FFFFFF',
        'text-background-opacity': 0.8,
        'text-background-padding': '2px',
        'transition-property': 'line-color, width',
        'transition-duration': '0.3s'
      }
    },
    {
      selector: 'edge:hover',
      style: {
        'width': (ele: any) => Math.max(3, ele.data('strength') * 4),
        'z-index': 9999
      }
    },
    {
      selector: 'edge:selected',
      style: {
        'line-color': '#EF4444',
        'target-arrow-color': '#EF4444',
        'width': (ele: any) => Math.max(4, ele.data('strength') * 5),
        'z-index': 10000
      }
    },
    // ENABLES edge with animation
    {
      selector: '.edge-ENABLES',
      style: {
        'line-color': '#10B981',
        'target-arrow-color': '#10B981',
        'line-style': 'solid'
      }
    },
    // Animated edge for active flows
    {
      selector: '.active-flow',
      style: {
        'line-color': '#F59E0B',
        'target-arrow-color': '#F59E0B',
        'width': 4,
        'line-style': 'dashed',
        'line-dash-pattern': [6, 3],
        'line-dash-offset': 24
      }
    }
  ];

  // Handle element selection with enhanced feedback
  const handleCyReady = (cy: any) => {
    cyRef.current = cy;

    // Add animations
    let animationInterval: any = null;
    if (animationEnabled) {
      // Animate active flows
      animationInterval = setInterval(() => {
        if (cy && !cy.destroyed()) {
          cy.edges('.active-flow').forEach((edge: any) => {
            const currentOffset = edge.style('line-dash-offset');
            edge.style('line-dash-offset', currentOffset - 1);
          });
        }
      }, 50);
    }
    
    // Clean up interval when component unmounts
    cy.on('destroy', () => {
      if (animationInterval) {
        clearInterval(animationInterval);
      }
    });

    // Enhanced selection handlers
    cy.on('select', 'node', (event: any) => {
      const node = event.target;
      const nodeData = graphData?.nodes.find((n: any) => n.id === node.id());
      if (nodeData && onNodeSelect) {
        onNodeSelect(node.id(), nodeData);
      }
      setSelectedElement({ type: 'node', data: node.data() });
      
      // Highlight connected edges
      node.connectedEdges().addClass('highlighted');
    });

    cy.on('select', 'edge', (event: any) => {
      const edge = event.target;
      const edgeData = graphData?.edges.find((e: any) => 
        e.source === edge.data('source') && e.target === edge.data('target')
      );
      if (edgeData && onEdgeSelect) {
        onEdgeSelect(edge.id(), edgeData);
      }
      setSelectedElement({ type: 'edge', data: edge.data() });
    });

    cy.on('unselect', () => {
      setSelectedElement(null);
      cy.edges('.highlighted').removeClass('highlighted');
    });

    // Add double-click to focus
    cy.on('dbltap', 'node', (event: any) => {
      event.preventDefault();
      const node = event.target;
      
      // Stop any ongoing animations
      cy.stop();
      
      // Animate to the node with a reasonable zoom level
      cy.animate({
        center: { eles: node },
        zoom: Math.min(cy.zoom() * 1.5, 3) // Increment zoom by 50%, max 3x
      }, {
        duration: 500,
        queue: false // Don't queue animations
      });
    });
  };

  // Control functions
  const fitGraph = () => {
    if (cyRef.current) {
      cyRef.current.fit(undefined, 50);
    }
  };

  const centerGraph = () => {
    if (cyRef.current) {
      cyRef.current.center();
    }
  };

  const resetZoom = () => {
    if (cyRef.current) {
      cyRef.current.zoom(1);
      cyRef.current.center();
    }
  };

  const runLayout = () => {
    if (cyRef.current) {
      const newLayout = cyRef.current.layout(layout);
      newLayout.run();
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
      {/* Enhanced Controls */}
      <div className="flex justify-between items-center flex-wrap gap-2">
        <div className="flex space-x-2">
          <button
            onClick={fitGraph}
            className="px-3 py-1 bg-blue-500 text-white rounded hover:bg-blue-600 text-sm transition-colors"
          >
            Fit
          </button>
          <button
            onClick={centerGraph}
            className="px-3 py-1 bg-green-500 text-white rounded hover:bg-green-600 text-sm transition-colors"
          >
            Center
          </button>
          <button
            onClick={resetZoom}
            className="px-3 py-1 bg-gray-500 text-white rounded hover:bg-gray-600 text-sm transition-colors"
          >
            Reset Zoom
          </button>
          <button
            onClick={runLayout}
            className="px-3 py-1 bg-purple-500 text-white rounded hover:bg-purple-600 text-sm transition-colors"
          >
            Re-layout
          </button>
          <button
            onClick={exportImage}
            className="px-3 py-1 bg-indigo-500 text-white rounded hover:bg-indigo-600 text-sm transition-colors"
          >
            Export PNG
          </button>
        </div>
        
        {/* Layout selector */}
        <div className="flex items-center space-x-2">
          <label className="text-sm text-gray-600">Layout:</label>
          <select
            value={layoutType}
            onChange={(e) => setLayoutType(e.target.value)}
            className="px-2 py-1 border border-gray-300 rounded text-sm"
          >
            <option value="auto">Auto</option>
            <option value="dagre">Hierarchical</option>
            <option value="cola">Force-directed</option>
            <option value="cose-bilkent">Spring</option>
            <option value="circular">Circular</option>
          </select>
          
          <label className="flex items-center space-x-1">
            <input
              type="checkbox"
              checked={animationEnabled}
              onChange={(e) => setAnimationEnabled(e.target.checked)}
              className="rounded"
            />
            <span className="text-sm text-gray-600">Animations</span>
          </label>
        </div>
        
        <div className="text-sm text-gray-600">
          {graphData?.nodes?.length || 0} nodes, {graphData?.edges?.length || 0} edges
        </div>
      </div>

      {/* Graph Container with gradient border */}
      <div className="relative">
        <div className="h-[600px] border-2 border-gradient-to-r from-blue-400 to-purple-500 rounded-lg overflow-hidden shadow-lg">
          {cytoscapeElements.length === 0 ? (
            <div className="h-full flex items-center justify-center text-gray-500">
              No graph elements to display
            </div>
          ) : (
            <div className="h-full bg-gradient-to-br from-gray-50 to-gray-100">
              <CytoscapeComponent
                elements={cytoscapeElements}
                layout={layout}
                stylesheet={stylesheet}
                style={{ width: '100%', height: '100%' }}
                cy={handleCyReady}
                wheelSensitivity={0.2}
                minZoom={0.1}
                maxZoom={5}
              />
            </div>
          )}
        </div>

        {/* Enhanced Element Info Panel */}
        {selectedElement && (
          <div className="absolute top-2 right-2 bg-white border-2 border-gray-200 rounded-lg p-4 shadow-xl max-w-sm backdrop-blur-sm bg-opacity-95">
            <h4 className="font-bold text-sm mb-3 text-gray-800">
              {selectedElement.type === 'node' ? '🔵 Node' : '➡️ Edge'} Details
            </h4>
            <div className="text-xs space-y-2">
              <div className="flex justify-between">
                <span className="font-semibold text-gray-600">ID:</span>
                <span className="text-gray-800">{selectedElement.data.id}</span>
              </div>
              <div className="flex justify-between">
                <span className="font-semibold text-gray-600">Type:</span>
                <span className="text-gray-800">{selectedElement.data.nodeType || selectedElement.data.edgeType}</span>
              </div>
              {selectedElement.data.label && (
                <div>
                  <span className="font-semibold text-gray-600">Label:</span>
                  <p className="text-gray-800 mt-1">{selectedElement.data.label}</p>
                </div>
              )}
              {selectedElement.data.confidence && (
                <div className="flex justify-between">
                  <span className="font-semibold text-gray-600">Confidence:</span>
                  <span className={`px-2 py-1 rounded text-xs ${
                    selectedElement.data.confidence > 0.8 ? 'bg-green-100 text-green-800' :
                    selectedElement.data.confidence > 0.5 ? 'bg-yellow-100 text-yellow-800' :
                    'bg-red-100 text-red-800'
                  }`}>
                    {(selectedElement.data.confidence * 100).toFixed(0)}%
                  </span>
                </div>
              )}
              {selectedElement.type === 'edge' && (
                <>
                  <div className="flex justify-between">
                    <span className="font-semibold text-gray-600">Source:</span>
                    <span className="text-gray-800">{selectedElement.data.source}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="font-semibold text-gray-600">Target:</span>
                    <span className="text-gray-800">{selectedElement.data.target}</span>
                  </div>
                </>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Enhanced Legend */}
      <div className="bg-gradient-to-r from-gray-50 to-gray-100 p-4 rounded-lg shadow-inner">
        <h4 className="font-bold text-sm mb-3 text-gray-800">Interactive Legend</h4>
        <div className="grid grid-cols-2 gap-4">
          {/* Attack Types */}
          <div>
            <div className="font-semibold text-xs mb-2 text-gray-700">Attack Types:</div>
            <div className="space-y-1 text-xs">
              <div className="flex items-center space-x-2 hover:bg-white p-1 rounded cursor-pointer transition-colors">
                <div className="w-4 h-4 bg-gradient-to-br from-red-500 to-red-700 transform rotate-45"></div>
                <span>MITM Indicator</span>
              </div>
              <div className="flex items-center space-x-2 hover:bg-white p-1 rounded cursor-pointer transition-colors">
                <div className="w-4 h-4 bg-gradient-to-br from-red-700 to-red-900" style={{ clipPath: 'polygon(50% 0%, 61% 35%, 98% 35%, 68% 57%, 79% 91%, 50% 70%, 21% 91%, 32% 57%, 2% 35%, 39% 35%)' }}></div>
                <span>DoS Attack</span>
              </div>
              <div className="flex items-center space-x-2 hover:bg-white p-1 rounded cursor-pointer transition-colors">
                <div className="w-4 h-4 bg-gradient-to-br from-yellow-500 to-yellow-700" style={{ clipPath: 'polygon(50% 0%, 0% 100%, 100% 100%)' }}></div>
                <span>Protocol Manipulation</span>
              </div>
              <div className="flex items-center space-x-2 hover:bg-white p-1 rounded cursor-pointer transition-colors">
                <div className="w-4 h-4 bg-gradient-to-br from-blue-500 to-blue-700 rounded"></div>
                <span>Enumeration</span>
              </div>
              <div className="flex items-center space-x-2 hover:bg-white p-1 rounded cursor-pointer transition-colors">
                <div className="w-4 h-3 bg-gradient-to-br from-purple-500 to-purple-700 rounded-full"></div>
                <span>Timing Anomaly</span>
              </div>
            </div>
          </div>
          
          {/* Visual Indicators */}
          <div>
            <div className="font-semibold text-xs mb-2 text-gray-700">Visual Indicators:</div>
            <div className="space-y-1 text-xs">
              <div className="flex items-center space-x-2">
                <div className="w-4 h-4 border-2 border-green-500 rounded shadow-md"></div>
                <span>High Confidence (&gt;80%)</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-4 h-4 border-2 border-dashed border-gray-400 rounded"></div>
                <span>Low Confidence (&lt;50%)</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-8 h-0.5 bg-green-500"></div>
                <span>ENABLES Relationship</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-8 h-0.5 bg-orange-500" style={{ borderTop: '2px dashed #F59E0B' }}></div>
                <span>Active Flow</span>
              </div>
            </div>
          </div>
        </div>
        
        <div className="mt-3 text-xs text-gray-600">
          💡 <strong>Tips:</strong> Hover to highlight • Double-click to zoom • Drag to pan • Scroll to zoom
        </div>
      </div>
    </div>
  );
};

export default GraphVisualizationEnhanced;
