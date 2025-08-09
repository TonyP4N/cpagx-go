import React, { useCallback, useMemo, useState } from 'react';
import { useForm, SubmitHandler } from 'react-hook-form';
import useSWR from 'swr';
import { useDropzone } from 'react-dropzone';
import toast, { Toaster } from 'react-hot-toast';
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
  CogIcon
} from '@heroicons/react/24/outline';

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

  const { register: registerDevice, handleSubmit: handleDeviceSubmit, reset: resetDevice, formState: { errors: deviceErrors } } = useForm<DeviceFormInput>();
  const { register: registerRule, handleSubmit: handleRuleSubmit, reset: resetRule, formState: { errors: ruleErrors } } = useForm<RuleFormInput>();

  const { data: taskStatus, mutate } = useSWR<TaskStatus>(
    taskId ? `/api/v1/cpag/status/${taskId}` : null,
    fetcher,
    { refreshInterval: taskId ? 3000 : 0, keepPreviousData: true }
  );

  React.useEffect(() => { mutate(); }, [taskId, mutate]);

  const onDrop = useCallback((accepted: File[]) => {
    if (!accepted.length) return;
    const file = accepted[0];
    const ext = file.name.toLowerCase().split('.').pop() || '';
    if (!['pcap', 'pcapng', 'csv'].includes(ext)) {
      toast.error('Only .pcap / .pcapng / .csv files are supported');
      return;
    }
    if (file.size > 100 * 1024 * 1024) { // 100MB
      toast.error('File size must be less than 100MB');
      return;
    }
    setSelectedFile(file);
    toast.success(`File selected: ${file.name} (${(file.size / 1024 / 1024).toFixed(2)}MB)`);
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
    body.append('file', selectedFile);
    body.append('device_map', JSON.stringify(deviceMap));
    body.append('rules', JSON.stringify(customRules));
    body.append('output_format', 'tcity');

    try {
      const res = await fetch('/api/v1/cpag/generate', { method: 'POST', body });
      if (!res.ok) throw new Error(await res.text());
      const json = await res.json();
      setTaskId(json.id);
      toast.success('Analysis task started successfully');
    } catch (err: any) {
      toast.error(`Failed to start analysis: ${err.message || 'unknown error'}`);
    } finally {
      setIsLoading(false);
    }
  };

  const downloadResult = async () => {
    if (!taskId) return;
    try {
      const res = await fetch(`/api/v1/cpag/result/${taskId}`);
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
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50 text-slate-800">
      <Toaster 
        position="top-center" 
        toastOptions={{
          duration: 4000,
          style: {
            background: '#363636',
            color: '#fff',
          },
        }}
      />
      
      {/* Header */}
      <header className="sticky top-0 z-10 backdrop-blur-md bg-white/90 border-b border-slate-200 shadow-sm">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl">
              <DocumentTextIcon className="h-8 w-8 text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-slate-800">CPAG Generator</h1>
              <p className="text-sm text-slate-500">Cyber-Physical Attack Graph Analysis</p>
            </div>
          </div>
          <button 
            className={`inline-flex items-center gap-2 rounded-xl px-6 py-3 font-medium transition-all duration-200 shadow-lg ${
              canStartAnalysis 
                ? 'bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 text-white transform hover:scale-105' 
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
        
        {/* Progress Bar */}
        {taskId && (
          <div className="w-full h-1 bg-slate-200">
            <div 
              className="h-full transition-all duration-1000 ease-out rounded-r-full" 
              style={{ 
                width: `${progress}%`, 
                background: 'linear-gradient(to right, #6366f1, #8b5cf6, #ec4899)' 
              }} 
            />
          </div>
        )}
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto p-6">
        <div className="grid lg:grid-cols-3 gap-8">
          
          {/* Left Column - Input Controls */}
          <div className="lg:col-span-2 space-y-6">
            
            {/* File Upload */}
            <div className="bg-white/80 backdrop-blur-sm rounded-2xl shadow-xl border border-slate-200 overflow-hidden">
              <div className="p-6 border-b border-slate-100">
                <h2 className="text-xl font-semibold text-slate-800 flex items-center gap-2">
                  <CloudArrowUpIcon className="h-6 w-6 text-indigo-600" />
                  File Upload
                </h2>
                <p className="text-sm text-slate-500 mt-1">Upload your network capture or CSV file for analysis</p>
              </div>
              <div 
                {...getRootProps()} 
                className={`p-8 text-center cursor-pointer transition-all duration-300 ${
                  isDragActive 
                    ? 'border-2 border-indigo-500 bg-indigo-50 scale-105' 
                    : 'border-2 border-dashed border-slate-300 hover:border-indigo-400 hover:bg-slate-50'
                }`}
              >
                <input {...getInputProps()} />
                <CloudArrowUpIcon className={`mx-auto h-16 w-16 transition-colors ${
                  isDragActive ? 'text-indigo-600' : 'text-slate-400'
                }`} />
                <p className="mt-4 text-lg font-medium text-slate-700">
                  {selectedFile ? (
                    <span className="text-indigo-600">{selectedFile.name}</span>
                  ) : (
                    'Drag & drop or click to upload'
                  )}
                </p>
                <p className="text-sm text-slate-500 mt-2">
                  Supports .pcap, .pcapng, .csv files (max 100MB)
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
                  <CogIcon className="h-6 w-6 text-indigo-600" />
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
                    className="flex-1 rounded-lg border border-slate-300 px-4 py-3 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all"
                  />
                  <input 
                    {...registerDevice('name', { required: 'Device name is required' })} 
                    placeholder="Router" 
                    className="flex-1 rounded-lg border border-slate-300 px-4 py-3 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all"
                  />
                  <button 
                    type="submit" 
                    className="rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-3 font-medium transition-colors shadow-md hover:shadow-lg"
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
                            <div className="w-2 h-2 bg-indigo-500 rounded-full"></div>
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
                  <InformationCircleIcon className="h-6 w-6 text-indigo-600" />
                  Custom Rules
                </h2>
                <p className="text-sm text-slate-500 mt-1">Define custom analysis rules for attack detection</p>
              </div>
              <div className="p-6 space-y-4">
                <form onSubmit={handleRuleSubmit(submitRule)} className="flex gap-3">
                  <input 
                    {...registerRule('rule', { required: 'Rule is required' })} 
                    placeholder="Example: port_scan_threshold > 10" 
                    className="flex-1 rounded-lg border border-slate-300 px-4 py-3 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all"
                  />
                  <button 
                    type="submit" 
                    className="rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-3 font-medium transition-colors shadow-md hover:shadow-lg"
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
                    <ClockIcon className="h-6 w-6 text-indigo-600" />
                    Analysis Status
                  </h2>
                  <p className="text-sm text-slate-500 mt-1">Task ID: {taskId}</p>
                </div>
                <div className="p-6">
                  {taskStatus.status === 'processing' && (
                    <div className="text-center space-y-4">
                      <div className="relative">
                        <ArrowPathIcon className="h-12 w-12 animate-spin text-indigo-600 mx-auto" />
                        <div className="absolute inset-0 flex items-center justify-center">
                          <div className="w-8 h-8 bg-white rounded-full"></div>
                        </div>
                      </div>
                      <div>
                        <p className="text-lg font-medium text-slate-800">Processing...</p>
                        <p className="text-sm text-slate-500">Analyzing your file, please wait</p>
                      </div>
                      <div className="w-full bg-slate-200 rounded-full h-2">
                        <div className="bg-gradient-to-r from-indigo-500 to-purple-600 h-2 rounded-full animate-pulse" style={{ width: '60%' }}></div>
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
                  <span className="text-sm font-medium text-indigo-600">
                    {Object.keys(deviceMap).length}
                  </span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-slate-600">Custom Rules</span>
                  <span className="text-sm font-medium text-indigo-600">
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
          </div>
        </div>
      </main>
    </div>
  );
}
