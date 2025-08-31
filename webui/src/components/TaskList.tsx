import React, { useState, useMemo } from 'react';
import useSWR from 'swr';
import toast from 'react-hot-toast';
import { 
  DocumentArrowDownIcon, 
  EyeIcon, 
  ClockIcon, 
  CheckCircleIcon, 
  ExclamationTriangleIcon,
  ArrowPathIcon,
  ServerIcon,
  CalendarIcon,
  DocumentTextIcon,
  ChevronLeftIcon,
  ChevronRightIcon
} from '@heroicons/react/24/outline';

interface Task {
  task_id: string;
  status: 'processing' | 'completed' | 'failed';
  created_at: string;
  version: string;
  files?: string[];
  result_url?: string;
  file_size?: number;
  file_name?: string;
}

const fetcher = (url: string) => fetch(url).then(r => r.json());

export default function TaskList() {
  const [selectedVersion, setSelectedVersion] = useState<string>('all');
  const [previewTask, setPreviewTask] = useState<Task | null>(null);
  const [previewData, setPreviewData] = useState<any>(null);
  const [isLoadingPreview, setIsLoadingPreview] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 6;

  // 获取任务列表
  const { data: tasks, error, mutate } = useSWR<Task[]>(
    `/api/tasks/list${selectedVersion !== 'all' ? `?version=${selectedVersion}` : ''}`,
    fetcher,
    { refreshInterval: 10000 }
  );

  // 获取队列状态
  const { data: queueStatus } = useSWR('/api/tasks/queue/status', fetcher, {
    refreshInterval: 3000 // 减少轮询间隔以提高同步性
  });

  // 分页逻辑
  const paginatedTasks = useMemo(() => {
    if (!tasks) return [];
    const startIndex = (currentPage - 1) * itemsPerPage;
    const endIndex = startIndex + itemsPerPage;
    return tasks.slice(startIndex, endIndex);
  }, [tasks, currentPage, itemsPerPage]);

  const totalPages = useMemo(() => {
    if (!tasks) return 0;
    return Math.ceil(tasks.length / itemsPerPage);
  }, [tasks, itemsPerPage]);

  // 重置分页当版本过滤器改变时
  const handleVersionChange = (version: string) => {
    setSelectedVersion(version);
    setCurrentPage(1);
  };

  const handlePreview = async (task: Task) => {
    if (!task.result_url) {
      toast.error('No result available for preview');
      return;
    }

    setIsLoadingPreview(true);
    setPreviewTask(task);

    try {
      // 构建完整的API URL
      const version = task.version || 'v1';
      const apiUrl = `/api/${version}${task.result_url}`;
      
      // 尝试获取结果数据
      const res = await fetch(apiUrl);
      if (!res.ok) throw new Error('Failed to fetch result');
      
      const data = await res.json();
      setPreviewData(data);
    } catch (err: any) {
      toast.error(`Preview failed: ${err.message}`);
      setPreviewData(null);
    } finally {
      setIsLoadingPreview(false);
    }
  };

  const handleDownload = async (task: Task, filename: string) => {
    try {
      const version = task.version || 'v1';
      const res = await fetch(`/api/tasks/download/${task.task_id}/${filename}?version=${version}`);
      if (!res.ok) throw new Error('Download failed');
      
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
      
      // 智能文件名截断
      const displayName = filename.length > 25 ? filename.substring(0, 22) + '...' : filename;
      toast.success(`${displayName} downloaded successfully`);
    } catch (err: any) {
      toast.error(`Download failed: ${err.message}`);
    }
  };

  const formatFileSize = (bytes?: number) => {
    if (!bytes) return 'Unknown';
    const mb = bytes / 1024 / 1024;
    return `${mb.toFixed(2)} MB`;
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircleIcon className="h-5 w-5 text-green-600" />;
      case 'processing':
        return <ClockIcon className="h-5 w-5 text-yellow-600" />;
      case 'failed':
        return <ExclamationTriangleIcon className="h-5 w-5 text-red-600" />;
      default:
        return <ClockIcon className="h-5 w-5 text-slate-400" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'bg-green-50 border-green-200 text-green-700';
      case 'processing':
        return 'bg-yellow-50 border-yellow-200 text-yellow-700';
      case 'failed':
        return 'bg-red-50 border-red-200 text-red-700';
      default:
        return 'bg-slate-50 border-slate-200 text-slate-700';
    }
  };

  if (error) {
    return (
      <div className="bg-white/80 backdrop-blur-sm rounded-2xl shadow-xl border border-slate-200 p-6">
        <div className="text-center py-12">
          <ExclamationTriangleIcon className="h-12 w-12 text-red-500 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-slate-800 mb-2">Failed to load tasks</h3>
          <p className="text-slate-500 mb-4">{error.message}</p>
          <button 
            onClick={() => mutate()}
            className="inline-flex items-center gap-2 px-4 py-2 bg-emerald-600 text-white rounded-lg hover:bg-emerald-700 transition-colors"
          >
            <ArrowPathIcon className="h-4 w-4" />
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white/80 backdrop-blur-sm rounded-2xl shadow-xl border border-slate-200 p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-gradient-to-br from-emerald-500 to-teal-600 rounded-xl">
              <DocumentTextIcon className="h-6 w-6 text-white" />
            </div>
            <div>
              <h2 className="text-xl font-semibold text-slate-800">Task History</h2>
              <p className="text-sm text-slate-500">View and manage your analysis tasks</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right">
              <div className="text-sm text-slate-500">Queue Status</div>
                                  <div className="text-lg font-semibold text-emerald-600">
                      {queueStatus ? `${queueStatus.active_tasks}/${queueStatus.max_concurrent_tasks}` : '0/0'}
                    </div>
            </div>
          </div>
        </div>

        {/* Version Filter */}
        <div className="flex items-center gap-4 mb-6">
          <label className="text-sm font-medium text-slate-700">Filter by Version:</label>
          <select
            value={selectedVersion}
            onChange={(e) => handleVersionChange(e.target.value)}
            className="rounded-lg border border-slate-300 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent"
          >
            <option value="all">All Versions</option>
            <option value="v1">Version 1.0</option>
            <option value="v2">Version 2.0</option>
          </select>
        </div>

        {/* Tasks List */}
        <div className="space-y-4">
          {!tasks || tasks.length === 0 ? (
            <div className="text-center py-12">
              <DocumentTextIcon className="h-12 w-12 text-slate-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-slate-600 mb-2">No tasks found</h3>
              <p className="text-slate-500">Start a new analysis to see tasks here</p>
            </div>
          ) : (
            paginatedTasks.map((task) => (
              <div key={task.task_id} className="bg-white rounded-xl border border-slate-200 p-6 hover:shadow-lg transition-shadow">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    {getStatusIcon(task.status)}
                    <div>
                      <h3 className="font-semibold text-slate-800">Task {task.task_id.slice(0, 8)}...</h3>
                      <p className="text-sm text-slate-500">Version {task.version}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`px-3 py-1 rounded-full text-xs font-medium border ${getStatusColor(task.status)}`}>
                      {task.status}
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                  <div className="flex items-center gap-2 text-sm text-slate-600">
                    <CalendarIcon className="h-4 w-4" />
                    <span>{formatDate(task.created_at)}</span>
                  </div>
                  {task.file_name && (
                    <div className="flex items-center gap-2 text-sm text-slate-600">
                      <DocumentTextIcon className="h-4 w-4" />
                      <span>{task.file_name}</span>
                    </div>
                  )}
                  {task.file_size && (
                    <div className="flex items-center gap-2 text-sm text-slate-600">
                      <ServerIcon className="h-4 w-4" />
                      <span>{formatFileSize(task.file_size)}</span>
                    </div>
                  )}
                </div>

                {/* Action Buttons */}
                <div className="flex items-center gap-3">
                  {task.status === 'completed' && task.result_url && (
                                         <button
                       onClick={() => handlePreview(task)}
                       className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                     >
                       <EyeIcon className="h-4 w-4" />
                       Preview
                     </button>
                  )}
                  
                  {task.status === 'completed' && task.files && task.files.length > 0 && (
                    <div className="flex items-center gap-2">
                      {task.files.map((filename) => (
                        <button
                          key={filename}
                          onClick={() => handleDownload(task, filename)}
                          className="inline-flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
                        >
                          <DocumentArrowDownIcon className="h-4 w-4" />
                          Download {filename}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ))
          )}
        </div>

        {/* Pagination */}
        {tasks && tasks.length > itemsPerPage && (
          <div className="flex items-center justify-between mt-6 pt-6 border-t border-slate-200">
            <div className="text-sm text-slate-600">
              Showing {Math.min((currentPage - 1) * itemsPerPage + 1, tasks.length)} to {Math.min(currentPage * itemsPerPage, tasks.length)} of {tasks.length} tasks
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
                disabled={currentPage === 1}
                className={`inline-flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                  currentPage === 1
                    ? 'text-slate-400 cursor-not-allowed'
                    : 'text-slate-600 hover:text-slate-800 hover:bg-slate-100'
                }`}
              >
                <ChevronLeftIcon className="h-4 w-4" />
                Previous
              </button>
              
                                 <div className="flex items-center gap-1">
                     {Array.from({ length: totalPages }, (_, i) => i + 1).map((page) => (
                       <button
                         key={page}
                         onClick={() => setCurrentPage(page)}
                         className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                           page === currentPage
                             ? 'bg-emerald-600 text-white'
                             : 'text-slate-600 hover:text-slate-800 hover:bg-slate-100'
                         }`}
                       >
                         {page}
                       </button>
                     ))}
                   </div>
              
              <button
                onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
                disabled={currentPage === totalPages}
                className={`inline-flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                  currentPage === totalPages
                    ? 'text-slate-400 cursor-not-allowed'
                    : 'text-slate-600 hover:text-slate-800 hover:bg-slate-100'
                }`}
              >
                Next
                <ChevronRightIcon className="h-4 w-4" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Preview Modal */}
      {previewTask && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-2xl shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden">
            <div className="p-6 border-b border-slate-200">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold text-slate-800">
                  Preview: {previewTask.task_id.slice(0, 8)}...
                </h3>
                <button
                  onClick={() => {
                    setPreviewTask(null);
                    setPreviewData(null);
                  }}
                  className="text-slate-400 hover:text-slate-600"
                >
                  ✕
                </button>
              </div>
            </div>
            
            <div className="p-6 overflow-auto max-h-[calc(90vh-120px)]">
              {isLoadingPreview ? (
                <div className="text-center py-12">
                  <ArrowPathIcon className="h-8 w-8 animate-spin text-indigo-600 mx-auto mb-4" />
                  <p className="text-slate-600">Loading preview...</p>
                </div>
              ) : previewData ? (
                <div className="space-y-4">
                  <div className="bg-slate-50 rounded-lg p-4">
                    <h4 className="font-medium text-slate-800 mb-2">CPAG Data Preview</h4>
                    <pre className="text-sm text-slate-700 overflow-auto max-h-96">
                      {JSON.stringify(previewData, null, 2)}
                    </pre>
                  </div>
                </div>
              ) : (
                <div className="text-center py-12">
                  <ExclamationTriangleIcon className="h-8 w-8 text-red-500 mx-auto mb-4" />
                  <p className="text-slate-600">Failed to load preview data</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
