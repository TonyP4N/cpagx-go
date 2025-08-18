import React, { useState } from 'react';
import Head from 'next/head';
import GraphTasksList from '../components/GraphTasksList';
import GraphVisualization from '../components/GraphVisualization';

const GraphPage: React.FC = () => {
  const [selectedTaskId, setSelectedTaskId] = useState<string>('');
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [selectedEdge, setSelectedEdge] = useState<any>(null);

  const handleTaskSelect = (taskId: string) => {
    setSelectedTaskId(taskId);
    // Clear previous selections when switching tasks
    setSelectedNode(null);
    setSelectedEdge(null);
  };

  const handleNodeSelect = (nodeId: string, nodeData: any) => {
    setSelectedNode({ id: nodeId, data: nodeData });
    setSelectedEdge(null);
  };

  const handleEdgeSelect = (edgeId: string, edgeData: any) => {
    setSelectedEdge({ id: edgeId, data: edgeData });
    setSelectedNode(null);
  };

  return (
    <>
      <Head>
        <title>CPAG Graph Visualization</title>
        <meta name="description" content="Interactive CPAG graph visualization" />
      </Head>

      <div className="min-h-screen bg-gray-50">
        <div className="container mx-auto px-4 py-8">
          {/* Header */}
          <div className="mb-8">
            <h1 className="text-3xl font-bold text-gray-900 mb-2">
              CPAG Graph Visualization
            </h1>
            <p className="text-gray-600">
              Interactive visualization of Cyber-Physical Attack Graphs stored in Neo4j
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
            {/* Left Sidebar - Tasks List */}
            <div className="lg:col-span-1">
              <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
                <GraphTasksList
                  onTaskSelect={handleTaskSelect}
                  selectedTaskId={selectedTaskId}
                />
              </div>

              {/* Selection Details */}
              {(selectedNode || selectedEdge) && (
                <div className="mt-4 bg-white rounded-lg shadow-sm border border-gray-200 p-4">
                  <h4 className="font-semibold mb-3">
                    {selectedNode ? 'Node Details' : 'Edge Details'}
                  </h4>
                  
                  {selectedNode && (
                    <div className="space-y-2 text-sm">
                      <div><strong>ID:</strong> {selectedNode.id}</div>
                      <div><strong>Type:</strong> {selectedNode.data.node_type}</div>
                      <div><strong>Task ID:</strong> {selectedNode.data.task_id}</div>
                      
                      {selectedNode.data.properties && (
                        <div>
                          <strong>Properties:</strong>
                          <pre className="mt-1 p-2 bg-gray-100 rounded text-xs overflow-auto max-h-32">
                            {JSON.stringify(selectedNode.data.properties, null, 2)}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}

                  {selectedEdge && (
                    <div className="space-y-2 text-sm">
                      <div><strong>Source:</strong> {selectedEdge.data.source}</div>
                      <div><strong>Target:</strong> {selectedEdge.data.target}</div>
                      <div><strong>Type:</strong> {selectedEdge.data.edge_type}</div>
                      <div><strong>Task ID:</strong> {selectedEdge.data.task_id}</div>
                      
                      {selectedEdge.data.properties && (
                        <div>
                          <strong>Properties:</strong>
                          <pre className="mt-1 p-2 bg-gray-100 rounded text-xs overflow-auto max-h-32">
                            {JSON.stringify(selectedEdge.data.properties, null, 2)}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Main Content - Graph Visualization */}
            <div className="lg:col-span-3">
              <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                {selectedTaskId ? (
                  <>
                    <div className="mb-4">
                      <h2 className="text-xl font-semibold mb-2">
                        Graph Visualization
                      </h2>
                      <p className="text-gray-600 text-sm">
                        Task ID: <span className="font-mono">{selectedTaskId}</span>
                      </p>
                    </div>
                    
                    <GraphVisualization
                      taskId={selectedTaskId}
                      onNodeSelect={handleNodeSelect}
                      onEdgeSelect={handleEdgeSelect}
                    />
                  </>
                ) : (
                  <div className="h-96 flex items-center justify-center text-gray-500">
                    <div className="text-center">
                      <div className="text-6xl mb-4">📊</div>
                      <h3 className="text-lg font-medium mb-2">No Task Selected</h3>
                      <p className="text-sm">
                        Select a task from the left sidebar to view its graph visualization
                      </p>
                    </div>
                  </div>
                )}
              </div>

              {/* Navigation Links */}
              <div className="mt-6 flex justify-center space-x-4">
                <a
                  href="/"
                  className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 transition-colors"
                >
                  ← Back to Home
                </a>
                <a
                  href="/api/graph/health"
                  target="_blank"
                  className="px-4 py-2 bg-green-500 text-white rounded hover:bg-green-600 transition-colors"
                >
                  Neo4j Health Check
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default GraphPage;