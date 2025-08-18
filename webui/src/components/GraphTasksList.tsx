import React, { useState, useEffect } from 'react';
import { TrashIcon, EyeIcon, GlobeAltIcon } from '@heroicons/react/24/outline';

interface TaskInfo {
  task_id: string;
  timestamp: string;
  node_count: number;
  edge_count: number;
}

interface GraphTasksListProps {
  onTaskSelect?: (taskId: string) => void;
  selectedTaskId?: string;
}

const GraphTasksList: React.FC<GraphTasksListProps> = ({
  onTaskSelect,
  selectedTaskId
}) => {
  const [tasks, setTasks] = useState<TaskInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [neo4jBrowserUrl, setNeo4jBrowserUrl] = useState<string | null>(null);

  // Fetch tasks from API
  const fetchTasks = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch('/api/graph/tasks');
      if (!response.ok) {
        throw new Error(`Failed to fetch tasks: ${response.statusText}`);
      }
      
      const data = await response.json();
      setTasks(data.tasks || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  // Fetch Neo4j browser URL
  const fetchNeo4jBrowserUrl = async () => {
    try {
      const response = await fetch('/api/graph/browser');
      if (response.ok) {
        const data = await response.json();
        setNeo4jBrowserUrl(data.browser_url);
      }
    } catch (err) {
      console.warn('Failed to fetch Neo4j browser URL:', err);
    }
  };

  useEffect(() => {
    fetchTasks();
    fetchNeo4jBrowserUrl();
  }, []);

  // Delete task
  const deleteTask = async (taskId: string) => {
    if (!confirm('Are you sure you want to delete this task?')) {
      return;
    }

    try {
      const response = await fetch(`/api/graph/tasks/${taskId}`, {
        method: 'DELETE'
      });
      
      if (!response.ok) {
        throw new Error(`Failed to delete task: ${response.statusText}`);
      }
      
      // Refresh the task list
      await fetchTasks();
      
      // If the deleted task was selected, clear selection
      if (selectedTaskId === taskId && onTaskSelect) {
        onTaskSelect('');
      }
    } catch (err) {
      alert(`Error deleting task: ${err instanceof Error ? err.message : 'Unknown error'}`);
    }
  };

  // Format timestamp
  const formatTimestamp = (timestamp: string) => {
    try {
      const date = new Date(timestamp);
      return date.toLocaleString();
    } catch {
      return timestamp;
    }
  };

  if (loading) {
    return (
      <div className="p-4">
        <div className="animate-pulse space-y-3">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-16 bg-gray-200 rounded"></div>
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-4">
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="text-red-600">Error: {error}</div>
          <button
            onClick={fetchTasks}
            className="mt-2 px-3 py-1 bg-red-100 text-red-700 rounded hover:bg-red-200 text-sm"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-semibold">Graph Tasks</h3>
        <div className="flex space-x-2">
          <button
            onClick={fetchTasks}
            className="px-3 py-1 bg-blue-500 text-white rounded hover:bg-blue-600 text-sm"
          >
            Refresh
          </button>
          {neo4jBrowserUrl && (
            <a
              href={neo4jBrowserUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="px-3 py-1 bg-green-500 text-white rounded hover:bg-green-600 text-sm flex items-center space-x-1"
            >
              <GlobeAltIcon className="w-4 h-4" />
              <span>Neo4j Browser</span>
            </a>
          )}
        </div>
      </div>

      {/* Tasks List */}
      {tasks.length === 0 ? (
        <div className="text-center py-8 text-gray-500">
          No graph tasks found. Generate some CPAG data first.
        </div>
      ) : (
        <div className="space-y-2 max-h-96 overflow-y-auto">
          {tasks.map((task) => (
            <div
              key={task.task_id}
              className={`border rounded-lg p-3 cursor-pointer transition-colors ${
                selectedTaskId === task.task_id
                  ? 'border-blue-500 bg-blue-50'
                  : 'border-gray-200 hover:border-gray-300 hover:bg-gray-50'
              }`}
              onClick={() => onTaskSelect && onTaskSelect(task.task_id)}
            >
              <div className="flex justify-between items-start">
                <div className="flex-1">
                  <div className="flex items-center space-x-2">
                    <span className="font-mono text-sm text-gray-600">
                      {task.task_id.substring(0, 8)}...
                    </span>
                    <span className="text-xs text-gray-400">
                      {formatTimestamp(task.timestamp)}
                    </span>
                  </div>
                  <div className="flex space-x-4 mt-1 text-sm text-gray-600">
                    <span>{task.node_count} nodes</span>
                    <span>{task.edge_count} edges</span>
                  </div>
                </div>
                <div className="flex space-x-1">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      if (onTaskSelect) {
                        onTaskSelect(task.task_id);
                      }
                    }}
                    className="p-1 text-blue-500 hover:text-blue-700"
                    title="View Graph"
                  >
                    <EyeIcon className="w-4 h-4" />
                  </button>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      deleteTask(task.task_id);
                    }}
                    className="p-1 text-red-500 hover:text-red-700"
                    title="Delete Task"
                  >
                    <TrashIcon className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default GraphTasksList;