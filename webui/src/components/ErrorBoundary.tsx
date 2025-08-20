import React from 'react';

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: any;
}

interface ErrorBoundaryProps {
  children: React.ReactNode;
  fallback?: React.ComponentType<{ error: Error; retry: () => void }>;
}

class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error, errorInfo: null };
  }

  componentDidCatch(error: Error, errorInfo: any) {
    console.error('Error caught by ErrorBoundary:', error, errorInfo);
    this.setState({
      hasError: true,
      error,
      errorInfo
    });
  }

  retry = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
  };

  render() {
    if (this.state.hasError) {
      const DefaultFallback = () => (
        <div className="h-96 bg-red-50 rounded-lg border border-red-200 flex items-center justify-center">
          <div className="text-center p-6">
            <div className="text-red-600 text-4xl mb-4">⚠️</div>
            <h3 className="text-lg font-semibold text-red-800 mb-2">
              Graph Visualization Error
            </h3>
            <p className="text-red-600 text-sm mb-4">
              {this.state.error?.message || 'An unexpected error occurred while rendering the graph.'}
            </p>
            <button
              onClick={this.retry}
              className="px-4 py-2 bg-red-500 text-white rounded hover:bg-red-600 transition-colors"
            >
              Try Again
            </button>
            <details className="mt-4 text-left">
              <summary className="cursor-pointer text-sm text-red-600 hover:text-red-800">
                Technical Details
              </summary>
              <pre className="mt-2 p-2 bg-red-100 rounded text-xs overflow-auto max-h-32 text-red-800">
                {this.state.error?.stack}
              </pre>
            </details>
          </div>
        </div>
      );

      const FallbackComponent = this.props.fallback || DefaultFallback;
      return <FallbackComponent error={this.state.error!} retry={this.retry} />;
    }

    return this.props.children;
  }
}

export default ErrorBoundary;