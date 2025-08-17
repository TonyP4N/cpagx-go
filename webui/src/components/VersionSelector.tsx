import React, { useState, useEffect } from 'react';
import { 
  CheckCircleIcon, 
  ExclamationTriangleIcon, 
  ArrowPathIcon,
  SparklesIcon,
  CogIcon
} from '@heroicons/react/24/outline';

interface VersionInfo {
  name: string;
  description: string;
  port: number;
  enabled: boolean;
  status: string;
}

interface VersionsResponse {
  versions: Record<string, VersionInfo>;
}

interface VersionSelectorProps {
  onVersionChange: (version: string) => void;
  currentVersion?: string;
}

const VersionSelector: React.FC<VersionSelectorProps> = ({ 
  onVersionChange, 
  currentVersion = 'v1' 
}) => {
  const [versions, setVersions] = useState<Record<string, VersionInfo>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isOpen, setIsOpen] = useState(false);

  useEffect(() => {
    fetchVersions();
  }, []);

  const fetchVersions = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/version/list');
      if (!response.ok) {
        throw new Error('Failed to fetch versions');
      }
      const data: VersionsResponse = await response.json();
      setVersions(data.versions);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const handleVersionChange = async (version: string) => {
    try {
      const response = await fetch('/api/version/switch', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ version }),
      });

      if (!response.ok) {
        throw new Error('Failed to switch version');
      }

      onVersionChange(version);
      setIsOpen(false);
    } catch (err) {
      console.error('Version switch failed:', err);
      setError(err instanceof Error ? err.message : 'Version switch failed');
    }
  };

  if (loading) {
    return (
      <div className="version-selector relative">
        <div className="flex items-center gap-2 px-4 py-2 bg-white/80 backdrop-blur-sm rounded-xl border border-slate-200 shadow-sm">
          <div className="animate-spin">
            <ArrowPathIcon className="h-4 w-4 text-indigo-600" />
          </div>
          <span className="text-sm text-slate-600">Loading version info...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="version-selector relative">
        <div className="flex items-center gap-2 px-4 py-2 bg-red-50 border border-red-200 rounded-xl">
          <ExclamationTriangleIcon className="h-4 w-4 text-red-500" />
          <span className="text-sm text-red-600">Connection failed</span>
          <button
            onClick={fetchVersions}
            className="ml-auto text-xs text-red-500 hover:text-red-700 underline"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  const availableVersions = Object.entries(versions).filter(
    ([_, info]) => info.enabled
  );

  const currentVersionInfo = versions[currentVersion];

  return (
    <div className="version-selector relative">
      {/* Version selector button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-3 px-4 py-2 bg-white/90 backdrop-blur-sm rounded-xl border border-slate-200 shadow-sm hover:shadow-md transition-all duration-200 hover:border-indigo-300 min-w-[200px]"
      >
        <div className="flex items-center gap-2">
          <CogIcon className="h-4 w-4 text-indigo-600" />
          <span className="text-sm font-medium text-slate-700">Processing Version</span>
        </div>
        
        {/* Current version status */}
        <div className="flex items-center gap-2 ml-auto">
          <div className="flex items-center gap-1">
            <span className="text-xs text-slate-500">v{currentVersion.slice(1)}</span>
            <div className={`w-2 h-2 rounded-full ${
              currentVersionInfo?.status === 'healthy' 
                ? 'bg-green-500 animate-pulse' 
                : 'bg-red-500'
            }`} />
          </div>
          <div className={`w-2 h-2 border-2 border-slate-300 rounded transition-transform ${
            isOpen ? 'rotate-180' : ''
          }`} />
        </div>
      </button>

      {/* Dropdown menu */}
      {isOpen && (
        <div className="absolute top-full left-0 right-0 mt-2 bg-white rounded-xl border border-slate-200 shadow-lg z-50 overflow-hidden">
          <div className="p-3 border-b border-slate-100">
            <div className="flex items-center gap-2 text-xs text-slate-500">
              <SparklesIcon className="h-3 w-3" />
              <span>Select processing service version</span>
            </div>
          </div>
          
          <div className="max-h-48 overflow-y-auto">
            {availableVersions.map(([version, info]) => (
              <button
                key={version}
                onClick={() => handleVersionChange(version)}
                className={`w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-slate-50 transition-colors ${
                  version === currentVersion ? 'bg-indigo-50 border-r-2 border-indigo-500' : ''
                }`}
              >
                {/* Version status icon */}
                <div className="flex-shrink-0">
                  {info.status === 'healthy' ? (
                    <CheckCircleIcon className="h-4 w-4 text-green-500" />
                  ) : (
                    <ExclamationTriangleIcon className="h-4 w-4 text-red-500" />
                  )}
                </div>

                {/* Version info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-slate-800">
                      {info.name}
                    </span>
                    <span className="text-xs text-slate-400">
                      ({version})
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 mt-1 truncate">
                    {info.description}
                  </p>
                </div>

                {/* Port info */}
                <div className="flex-shrink-0">
                  <span className="text-xs text-slate-400 font-mono">
                    :{info.port}
                  </span>
                </div>
              </button>
            ))}
          </div>

          {/* Current version info */}
          {currentVersionInfo && (
            <div className="p-3 bg-slate-50 border-t border-slate-100">
              <div className="flex items-center gap-2 text-xs text-slate-600">
                <CheckCircleIcon className="h-3 w-3 text-green-500" />
                <span>Currently using: {currentVersionInfo.name}</span>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Click outside to close dropdown */}
      {isOpen && (
        <div 
          className="fixed inset-0 z-40" 
          onClick={() => setIsOpen(false)}
        />
      )}
    </div>
  );
};

export default VersionSelector;
