import React, { useCallback, useMemo, useState, useEffect } from 'react';
import { useForm, SubmitHandler } from 'react-hook-form';
import useSWR from 'swr';
import { useDropzone } from 'react-dropzone';
import toast, { Toaster } from 'react-hot-toast';
import { useRouter } from 'next/router';
import { 
  ArrowPathIcon, 
  CloudArrowUpIcon, 
  DocumentArrowDownIcon, 
  PlayCircleIcon, 
  PlusIcon, 
  TrashIcon,
  InformationCircleIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  ClockIcon,
  DocumentTextIcon,
  CogIcon,
  ChartBarIcon,
  ServerIcon
} from '@heroicons/react/24/outline';

import VersionSelector from '../components/VersionSelector';
import TaskList from '../components/TaskList';
import { useTabState, useNavigation } from '../hooks/useRouteState';

interface TaskStatus {
  id: string;
  status: 'processing' | 'completed' | 'failed';
  created_at: string;
  result_url?: string;
  error?: string;
}

interface DeviceFormInput { ip: string; name: string; }

interface RuleFormInput { rule: string; }

const fetcher = (url: string) => fetch(url).then(r => r.json());

export default function HomePage() {
  const [taskId, setTaskId] = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [deviceMap, setDeviceMap] = useState<Record<string, string>>({});
  const [customRules, setCustomRules] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [currentVersion, setCurrentVersion] = useState('v1');
  
  // 使用自定义Hook管理标签状态
  const [activeTab, setActiveTab] = useTabState();
  const { goToGraph } = useNavigation();

  // 优化的标签切换函数
  const handleTabChange = useCallback((newTab: 'upload' | 'history' | 'active') => {
    setActiveTab(newTab);
    
    // 清除相关状态
    if (newTab !== 'active') {
      setTaskId(null);
    }
  }, [setActiveTab]);

  const { register: registerDevice, handleSubmit: handleDeviceSubmit, reset: resetDevice, formState: { errors: deviceErrors } } = useForm<DeviceFormInput>();
  const { register: registerRule, handleSubmit: handleRuleSubmit, reset: resetRule, formState: { errors: ruleErrors } } = useForm<RuleFormInput>();

  const { data: taskStatus, mutate } = useSWR<TaskStatus>(
    taskId ? `/api/${currentVersion}/cpag/status/${taskId}` : null,
    fetcher,
    { refreshInterval: taskId ? 3000 : 0, keepPreviousData: true }
  );

  // 获取队列状态
  const { data: queueStatus } = useSWR(`/api/${currentVersion}/cpag/queue/status`, fetcher, {
    refreshInterval: taskId ? 3000 : 10000 // 有任务时3秒，无任务时10秒
  });

  React.useEffect(() => { 
    mutate(); 
    // 如果任务完成，立即清除taskId以停止轮询
    if (taskStatus?.status === 'completed' || taskStatus?.status === 'failed') {
      setTaskId(null);
    }
  }, [taskId, mutate, taskStatus]);

  // 智能文件名截断函数
  const truncateFileName = (fileName: string, maxLength: number = 25) => {
    if (fileName.length <= maxLength) return fileName;
    
    const extension = fileName.split('.').pop();
    const nameWithoutExt = fileName.substring(0, fileName.lastIndexOf('.'));
    
    if (!extension || extension.length >= maxLength - 3) {
      return fileName.substring(0, maxLength - 3) + '...';
    }
    
    const availableLength = maxLength - extension.length - 3; // 3 for "..."
    return nameWithoutExt.substring(0, availableLength) + '...' + extension;
  };

  // 格式化文件大小的工具函数
  const formatFileSize = (bytes: number) => {
    const mb = bytes / 1024 / 1024;
    return `${mb.toFixed(2)}MB`;
  };

  const onDrop = useCallback((accepted: File[]) => {
    if (!accepted.length) return;
    const file = accepted[0];
    const ext = file.name.toLowerCase().split('.').pop() || '';
    if (!['pcap', 'pcapng', 'csv'].includes(ext)) {
      toast.error('Only .pcap / .pcapng / .csv files are supported');
      return;
    }
    if (file.size > 300 * 1024 * 1024) { // 300MB
      toast.error('File size must be less than 300MB');
      return;
    }
    setSelectedFile(file);
    
    // 使用智能文件名截断和格式化
    const displayName = truncateFileName(file.name);
    const fileSize = formatFileSize(file.size);
    toast.success(`File selected: ${displayName}\n(${fileSize})`);
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({ 
    onDrop, 
    multiple: false,
    accept: {
      'application/vnd.tcpdump.pcap': ['.pcap'],
      'application/vnd.tcpdump.pcapng': ['.pcapng'],
      'text/csv': ['.csv']
    }
  });

  const submitDevice: SubmitHandler<DeviceFormInput> = ({ ip, name }) => {
    if (deviceMap[ip]) {
      toast.error('IP address already mapped');
      return;
    }
    setDeviceMap(prev => ({ ...prev, [ip]: name }));
    resetDevice();
    toast.success(`Device mapped: ${ip} → ${name}`);
  };

  const submitRule: SubmitHandler<RuleFormInput> = ({ rule }) => {
    if (customRules.includes(rule)) {
      toast.error('Rule already exists');
      return;
    }
    setCustomRules(prev => [...prev, rule]);
    resetRule();
    toast.success('Custom rule added');
  };

  const removeDevice = (ip: string) => {
    setDeviceMap(prev => { const c = { ...prev }; delete c[ip]; return c; });
    toast.success('Device mapping removed');
  };

  const removeRule = (rule: string) => {
    setCustomRules(prev => prev.filter(r => r !== rule));
    toast.success('Custom rule removed');
  };

  const startGeneration = async () => {
    if (!selectedFile) return toast.error('Please upload a file first');
    
    setIsLoading(true);
    const body = new FormData();
    
    // 根据版本选择不同的参数名
    if (currentVersion === 'v1') {
      body.append('file', selectedFile);
    } else {
      // v2版本使用更具体的参数名
      const ext = selectedFile.name.toLowerCase().split('.').pop() || '';
      if (['pcap', 'pcapng'].includes(ext)) {
        body.append('pcap_file', selectedFile);
      } else if (ext === 'csv') {
        body.append('csv_file', selectedFile);
      }
    }
    
    body.append('device_map', JSON.stringify(deviceMap));
    body.append('rules', JSON.stringify(customRules));
    body.append('output_format', 'tcity');

    try {
      const res = await fetch(`/api/${currentVersion}/cpag/generate`, { method: 'POST', body });
      if (!res.ok) throw new Error(await res.text());
      const json = await res.json();
      setTaskId(json.id);
      toast.success('Analysis task started successfully');
      
      // 清空上传区域的文件
      setSelectedFile(null);
      
      // 切换到活跃任务标签
      setActiveTab('active');
    } catch (err: any) {
      toast.error(`Failed to start analysis: ${err.message || 'unknown error'}`);
    } finally {
      setIsLoading(false);
    }
  };

  const downloadResult = async () => {
    if (!taskId) return;
    try {
      const res = await fetch(`/api/${currentVersion}/cpag/result/${taskId}`);
      if (!res.ok) throw new Error('Failed to fetch result');
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cpag-${taskId}.json`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success('CPAG JSON downloaded successfully');
    } catch (e: any) {
      toast.error(e.message || 'Download failed');
    }
  };

  const progress = useMemo(() => {
    if (!taskStatus) return 0;
    if (taskStatus.status === 'processing') return 50;
    if (taskStatus.status === 'completed') return 100;
    return 0;
  }, [taskStatus]);

  const canStartAnalysis = selectedFile && !isLoading;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-emerald-50 to-teal-50 text-slate-800">
      <Toaster 
        position="top-center" 
        toastOptions={{
          duration: 4000,
          style: {
            background: '#1f2937',
            color: '#fff',
            maxWidth: 'min(400px, 90vw)',
            wordBreak: 'break-word',
            whiteSpace: 'pre-wrap',
            lineHeight: '1.5',
            padding: '16px 20px',
            borderRadius: '12px',
            fontSize: '14px',
            boxShadow: '0 10px 25px rgba(0, 0, 0, 0.2)',
            border: '1px solid rgba(255, 255, 255, 0.1)',
          },
          className: '!max-w-[min(400px,90vw)] !break-words !backdrop-blur-sm',
          success: {
            style: {
              background: 'linear-gradient(135deg, #059669, #047857)',
              border: '1px solid rgba(34, 197, 94, 0.3)',
            },
          },
          error: {
            style: {
              background: 'linear-gradient(135deg, #dc2626, #b91c1c)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
            },
          },
        }}
      />
      
      {/* Header */}
      <header className="sticky top-0 z-10 backdrop-blur-md bg-white/90 border-b border-slate-200 shadow-sm">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
                         <div className="p-2 bg-gradient-to-br from-emerald-500 to-teal-600 rounded-xl">
               <DocumentTextIcon className="h-8 w-8 text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-slate-800">CPAG Generator</h1>
              <p className="text-sm text-slate-500">Cyber-Physical Attack Graph Analysis</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <VersionSelector 
              currentVersion={currentVersion} 
              onVersionChange={setCurrentVersion} 
            />
            <button
              onClick={() => goToGraph()}
              className="inline-flex items-center gap-2 rounded-xl px-4 py-2 font-medium transition-all duration-200 shadow-md bg-blue-100 hover:bg-blue-200 text-blue-700 hover:text-blue-900"
            >
              <ChartBarIcon className="h-5 w-5" />
              Graph View
            </button>
            <button 
                             className={`inline-flex items-center gap-2 rounded-xl px-6 py-3 font-medium transition-all duration-200 shadow-lg ${
                 canStartAnalysis 
                   ? 'bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-700 hover:to-teal-700 text-white transform hover:scale-105' 
                   : 'bg-slate-200 text-slate-400 cursor-not-allowed'
               }`} 
              onClick={startGeneration}
              disabled={!canStartAnalysis}
            >
              {isLoading ? (
                <ArrowPathIcon className="h-5 w-5 animate-spin" />
              ) : (
                <PlayCircleIcon className="h-5 w-5" />
              )}
              {isLoading ? 'Starting...' : 'Start Analysis'}
            </button>
          </div>
        </div>
        
        {/* Progress Bar */}
        {taskId && (
          <div className="w-full h-1 bg-slate-200">
                         <div 
               className="h-full transition-all duration-1000 ease-out rounded-r-full" 
               style={{ 
                 width: `${progress}%`, 
                 background: 'linear-gradient(to right, #10b981, #14b8a6, #0d9488)' 
               }} 
             />
          </div>
        )}
      </header>

      {/* Navigation Tabs */}
      <div className="max-w-7xl mx-auto px-6 pt-6">
        <div className="flex space-x-1 bg-white/80 backdrop-blur-sm rounded-xl p-1 shadow-lg border border-slate-200">
          <button
            onClick={() => handleTabChange('upload')}
                         className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-lg font-medium transition-all duration-200 ${
               activeTab === 'upload'
                 ? 'bg-gradient-to-r from-emerald-600 to-teal-600 text-white shadow-md'
                 : 'text-slate-600 hover:text-slate-800 hover:bg-slate-100'
             }`}
          >
            <CloudArrowUpIcon className="h-5 w-5" />
            File Upload
          </button>
          <button
            onClick={() => handleTabChange('active')}
                         className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-lg font-medium transition-all duration-200 ${
               activeTab === 'active'
                 ? 'bg-gradient-to-r from-emerald-600 to-teal-600 text-white shadow-md'
                 : 'text-slate-600 hover:text-slate-800 hover:bg-slate-100'
             }`}
          >
            <ClockIcon className="h-5 w-5" />
            Active Tasks
            {queueStatus && queueStatus.active_tasks > 0 && (
              <span className="bg-white/20 text-white text-xs px-2 py-1 rounded-full">
                {queueStatus.active_tasks}
              </span>
            )}
          </button>
          <button
            onClick={() => handleTabChange('history')}
                         className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-lg font-medium transition-all duration-200 ${
               activeTab === 'history'
                 ? 'bg-gradient-to-r from-emerald-600 to-teal-600 text-white shadow-md'
                 : 'text-slate-600 hover:text-slate-800 hover:bg-slate-100'
             }`}
          >
            <ChartBarIcon className="h-5 w-5" />
            Task History
          </button>
        </div>
      </div>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto p-6 min-h-[calc(100vh-200px)]">
        
        {/* Upload Tab */}
        {activeTab === 'upload' && (
          <div className="grid lg:grid-cols-3 gap-8 min-h-[calc(100vh-300px)]" style={{ gridTemplateRows: '1fr', display: 'grid' }}>
            
            {/* Left Column - Input Controls */}
            <div className="lg:col-span-2 space-y-6">
              
              {/* File Upload */}
              <div className="bg-white/80 backdrop-blur-sm rounded-2xl shadow-xl border border-slate-200 overflow-hidden">
                <div className="p-6 border-b border-slate-100">
                                     <h2 className="text-xl font-semibold text-slate-800 flex items-center gap-2">
                     <CloudArrowUpIcon className="h-6 w-6 text-emerald-600" />
                     File Upload
                   </h2>
                  <p className="text-sm text-slate-500 mt-1">Upload your network capture or CSV file for analysis</p>
                </div>
                <div 
                  {...getRootProps()} 
                                     className={`p-8 text-center cursor-pointer transition-all duration-300 ${
                     isDragActive 
                       ? 'border-2 border-emerald-500 bg-emerald-50 scale-105' 
                       : 'border-2 border-dashed border-slate-300 hover:border-emerald-400 hover:bg-slate-50'
                   }`}
                >
                  <input {...getInputProps()} />
                                     <CloudArrowUpIcon className={`mx-auto h-16 w-16 transition-colors ${
                     isDragActive ? 'text-emerald-600' : 'text-slate-400'
                   }`} />
                  <p className="mt-4 text-lg font-medium text-slate-700">
                                         {selectedFile ? (
                       <span className="text-emerald-600">{selectedFile.name}</span>
                     ) : (
                      'Drag & drop or click to upload'
                    )}
                  </p>
                  <p className="text-sm text-slate-500 mt-2">
                    Supports .pcap, .pcapng, .csv files (max 300MB)
                  </p>
                  {selectedFile && (
                    <div className="mt-4 p-3 bg-green-50 rounded-lg border border-green-200">
                      <div className="flex items-center gap-2 text-green-700">
                        <CheckCircleIcon className="h-5 w-5" />
                        <span className="text-sm font-medium">
                          File ready: {(selectedFile.size / 1024 / 1024).toFixed(2)}MB
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Device Mapping */}
              <div className="bg-white/80 backdrop-blur-sm rounded-2xl shadow-xl border border-slate-200">
                <div className="p-6 border-b border-slate-100">
                                     <h2 className="text-xl font-semibold text-slate-800 flex items-center gap-2">
                     <CogIcon className="h-6 w-6 text-emerald-600" />
                     Device Mapping
                   </h2>
                  <p className="text-sm text-slate-500 mt-1">Map IP addresses to meaningful device names</p>
                </div>
                <div className="p-6 space-y-4">
                  <form onSubmit={handleDeviceSubmit(submitDevice)} className="flex flex-col sm:flex-row gap-3">
                                         <input 
                       {...registerDevice('ip', { 
                         required: 'IP address is required',
                         pattern: {
                           value: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
                           message: 'Please enter a valid IP address'
                         }
                       })} 
                       placeholder="192.168.1.1" 
                       className="flex-1 rounded-lg border border-slate-300 px-4 py-3 focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent transition-all"
                     />
                                         <input 
                       {...registerDevice('name', { required: 'Device name is required' })} 
                       placeholder="Router" 
                       className="flex-1 rounded-lg border border-slate-300 px-4 py-3 focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent transition-all"
                     />
                    <button 
                      type="submit" 
                      className="rounded-lg bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 font-medium transition-colors shadow-md hover:shadow-lg"
                    >
                      Add
                    </button>
                  </form>
                  
                  {deviceErrors.ip && (
                    <p className="text-red-500 text-sm flex items-center gap-1">
                      <ExclamationTriangleIcon className="h-4 w-4" />
                      {deviceErrors.ip.message}
                    </p>
                  )}
                  {deviceErrors.name && (
                    <p className="text-red-500 text-sm flex items-center gap-1">
                      <ExclamationTriangleIcon className="h-4 w-4" />
                      {deviceErrors.name.message}
                    </p>
                  )}

                  {Object.keys(deviceMap).length > 0 && (
                    <div className="space-y-2">
                      <h3 className="text-sm font-medium text-slate-700">Mapped Devices ({Object.keys(deviceMap).length})</h3>
                      <div className="max-h-48 overflow-y-auto space-y-2 pr-2">
                        {Object.entries(deviceMap).map(([ip, name]) => (
                          <div key={ip} className="flex items-center justify-between bg-slate-50 rounded-lg px-4 py-3 border border-slate-200">
                            <div className="flex items-center gap-3">
                              <div className="w-2 h-2 bg-emerald-500 rounded-full"></div>
                              <span className="font-mono text-sm text-slate-700">{ip}</span>
                              <span className="text-slate-400">→</span>
                              <span className="font-medium text-slate-800">{name}</span>
                            </div>
                            <button
                              onClick={() => removeDevice(ip)}
                              className="p-1 text-slate-400 hover:text-red-500 transition-colors rounded"
                            >
                              <TrashIcon className="h-4 w-4" />
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Custom Rules */}
              <div className="bg-white/80 backdrop-blur-sm rounded-2xl shadow-xl border border-slate-200">
                <div className="p-6 border-b border-slate-100">
                  <h2 className="text-xl font-semibold text-slate-800 flex items-center gap-2">
                    <InformationCircleIcon className="h-6 w-6 text-emerald-600" />
                    Custom Rules
                  </h2>
                  <p className="text-sm text-slate-500 mt-1">Define custom analysis rules for attack detection</p>
                </div>
                <div className="p-6 space-y-4">
                  <form onSubmit={handleRuleSubmit(submitRule)} className="flex gap-3">
                    <input 
                      {...registerRule('rule', { required: 'Rule is required' })} 
                      placeholder="Example: port_scan_threshold > 10" 
                      className="flex-1 rounded-lg border border-slate-300 px-4 py-3 focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent transition-all"
                    />
                    <button 
                      type="submit" 
                      className="rounded-lg bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 font-medium transition-colors shadow-md hover:shadow-lg"
                    >
                      Add
                    </button>
                  </form>
                  
                  {ruleErrors.rule && (
                    <p className="text-red-500 text-sm flex items-center gap-1">
                      <ExclamationTriangleIcon className="h-4 w-4" />
                      {ruleErrors.rule.message}
                    </p>
                  )}

                  {customRules.length > 0 && (
                    <div className="space-y-2">
                      <h3 className="text-sm font-medium text-slate-700">Custom Rules ({customRules.length})</h3>
                      <div className="max-h-48 overflow-y-auto space-y-2 pr-2">
                        {customRules.map((rule, index) => (
                          <div key={index} className="flex items-center justify-between bg-slate-50 rounded-lg px-4 py-3 border border-slate-200">
                            <span className="font-mono text-sm text-slate-700 flex-1 mr-3">{rule}</span>
                            <button
                              onClick={() => removeRule(rule)}
                              className="p-1 text-slate-400 hover:text-red-500 transition-colors rounded flex-shrink-0"
                            >
                              <TrashIcon className="h-4 w-4" />
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Right Column - Status & Results */}
            <div className="space-y-6">
              
              {/* Analysis Status */}
              {taskStatus && (
                <div className="bg-white/80 backdrop-blur-sm rounded-2xl shadow-xl border border-slate-200 overflow-hidden">
                  <div className="p-6 border-b border-slate-100">
                    <h2 className="text-xl font-semibold text-slate-800 flex items-center gap-2">
                      <ClockIcon className="h-6 w-6 text-emerald-600" />
                      Analysis Status
                    </h2>
                    <p className="text-sm text-slate-500 mt-1">Task ID: {taskId}</p>
                  </div>
                  <div className="p-6">
                    {taskStatus.status === 'processing' && (
                      <div className="text-center space-y-4">
                        <div className="relative">
                          <ArrowPathIcon className="h-12 w-12 animate-spin text-emerald-600 mx-auto" />
                          <div className="absolute inset-0 flex items-center justify-center">
                            <div className="w-8 h-8 bg-white rounded-full"></div>
                          </div>
                        </div>
                        <div>
                          <p className="text-lg font-medium text-slate-800">Processing...</p>
                          <p className="text-sm text-slate-500">Analyzing your file, please wait</p>
                        </div>
                        <div className="w-full bg-slate-200 rounded-full h-2">
                          <div className="bg-gradient-to-r from-emerald-500 to-teal-600 h-2 rounded-full animate-pulse" style={{ width: '60%' }}></div>
                        </div>
                      </div>
                    )}
                    
                    {taskStatus.status === 'completed' && (
                      <div className="text-center space-y-4">
                        <div className="p-4 bg-green-100 rounded-full w-fit mx-auto">
                          <CheckCircleIcon className="h-12 w-12 text-green-600" />
                        </div>
                        <div>
                          <p className="text-lg font-medium text-green-700">Analysis Complete!</p>
                          <p className="text-sm text-slate-500">Your CPAG has been generated successfully</p>
                        </div>
                        <button 
                          onClick={downloadResult} 
                          className="w-full rounded-xl bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white px-6 py-4 font-medium transition-all duration-200 shadow-lg hover:shadow-xl transform hover:scale-105 inline-flex items-center justify-center gap-2"
                        >
                          <DocumentArrowDownIcon className="h-5 w-5" />
                          Download CPAG JSON
                        </button>
                      </div>
                    )}
                    
                    {taskStatus.status === 'failed' && (
                      <div className="text-center space-y-4">
                        <div className="p-4 bg-red-100 rounded-full w-fit mx-auto">
                          <ExclamationTriangleIcon className="h-12 w-12 text-red-600" />
                        </div>
                        <div>
                          <p className="text-lg font-medium text-red-700">Analysis Failed</p>
                          <p className="text-sm text-slate-500">Something went wrong during processing</p>
                        </div>
                        <div className="p-4 bg-red-50 rounded-lg border border-red-200">
                          <p className="text-sm text-red-700 font-mono">{taskStatus.error}</p>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Quick Stats */}
              <div className="bg-white/80 backdrop-blur-sm rounded-2xl shadow-xl border border-slate-200 p-6">
                <h3 className="text-lg font-semibold text-slate-800 mb-4">Quick Stats</h3>
                <div className="space-y-3">
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-slate-600">File Uploaded</span>
                    <span className={`text-sm font-medium ${selectedFile ? 'text-green-600' : 'text-slate-400'}`}>
                      {selectedFile ? 'Yes' : 'No'}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-slate-600">Devices Mapped</span>
                    <span className="text-sm font-medium text-emerald-600">
                      {Object.keys(deviceMap).length}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-slate-600">Custom Rules</span>
                    <span className="text-sm font-medium text-emerald-600">
                      {customRules.length}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-slate-600">Analysis Status</span>
                    <span className={`text-sm font-medium ${
                      !taskStatus ? 'text-slate-400' :
                      taskStatus.status === 'processing' ? 'text-yellow-600' :
                      taskStatus.status === 'completed' ? 'text-green-600' :
                      'text-red-600'
                    }`}>
                      {!taskStatus ? 'Not Started' : 
                       taskStatus.status === 'processing' ? 'Processing' :
                       taskStatus.status === 'completed' ? 'Completed' : 'Failed'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Queue Status */}
              {queueStatus && (
                <div className="bg-white/80 backdrop-blur-sm rounded-2xl shadow-xl border border-slate-200 p-6">
                  <h3 className="text-lg font-semibold text-slate-800 mb-4 flex items-center gap-2">
                    <ServerIcon className="h-5 w-5 text-emerald-600" />
                    Queue Status
                  </h3>
                  <div className="space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-slate-600">Active Tasks</span>
                      <span className="text-sm font-medium text-emerald-600">
                        {queueStatus.active_tasks}
                      </span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-slate-600">Available Slots</span>
                      <span className="text-sm font-medium text-green-600">
                        {queueStatus.available_slots}
                      </span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-slate-600">Queue Health</span>
                      <span className={`text-sm font-medium ${queueStatus.queue_healthy ? 'text-green-600' : 'text-red-600'}`}>
                        {queueStatus.queue_healthy ? 'Healthy' : 'Unhealthy'}
                      </span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Active Tasks Tab */}
        {activeTab === 'active' && (
          <div className="space-y-6 min-h-[calc(100vh-300px)] flex flex-col">
            <div className="bg-white/80 backdrop-blur-sm rounded-2xl shadow-xl border border-slate-200 p-6 flex-1">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-gradient-to-br from-emerald-500 to-teal-600 rounded-xl">
                    <ClockIcon className="h-6 w-6 text-white" />
                  </div>
                  <div>
                    <h2 className="text-xl font-semibold text-slate-800">Active Tasks</h2>
                    <p className="text-sm text-slate-500">Monitor currently running analysis tasks</p>
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
              
              {/* Active Tasks List */}
              <div className="space-y-4">
                {taskStatus && taskStatus.status === 'processing' && (
                  <div className="bg-gradient-to-r from-emerald-50 to-teal-50 rounded-xl p-6 border border-emerald-200">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-4">
                        <div className="relative">
                          <ArrowPathIcon className="h-8 w-8 animate-spin text-emerald-600" />
                        </div>
                        <div>
                          <h3 className="font-semibold text-slate-800">Current Task</h3>
                          <p className="text-sm text-slate-600">Task ID: {taskId}</p>
                          <p className="text-sm text-slate-500">Started: {new Date(taskStatus.created_at).toLocaleString()}</p>
                        </div>
                      </div>
                      <div className="text-right">
                        <div className="text-sm text-slate-500">Progress</div>
                        <div className="text-lg font-semibold text-emerald-600">{progress}%</div>
                      </div>
                    </div>
                    <div className="mt-4 w-full bg-slate-200 rounded-full h-2">
                      <div 
                        className="bg-gradient-to-r from-emerald-500 to-teal-600 h-2 rounded-full transition-all duration-1000" 
                        style={{ width: `${progress}%` }}
                      />
                    </div>
                  </div>
                )}
                
                {(!taskStatus || taskStatus.status !== 'processing') && (
                  <div className="text-center py-12">
                    <ClockIcon className="h-12 w-12 text-slate-400 mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-slate-600 mb-2">No Active Tasks</h3>
                    <p className="text-slate-500">Start a new analysis to see active tasks here</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Task History Tab */}
        {activeTab === 'history' && (
          <TaskList />
        )}
      </main>
    </div>
  );
}
