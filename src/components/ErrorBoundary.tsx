/**
 * Error Boundary Component
 * Catches React errors and provides crash recovery UI
 */

import React, { Component, ReactNode } from 'react';
import { appStore } from '@/stores/appStore';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: React.ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
    };
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return {
      hasError: true,
      error,
    };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo): void {
    console.error('❌ React Error Boundary caught an error:', error, errorInfo);

    this.setState({
      error,
      errorInfo,
    });

    // Log error to storage for debugging
    this.logErrorToStorage(error, errorInfo);
  }

  private async logErrorToStorage(error: Error, errorInfo: React.ErrorInfo): Promise<void> {
    try {
      const errorLog = {
        timestamp: Date.now(),
        message: error.message,
        stack: error.stack,
        componentStack: errorInfo.componentStack,
      };

      const result = await chrome.storage.local.get(['xcalibr_error_logs']);
      const logs = (result.xcalibr_error_logs || []) as typeof errorLog[];
      logs.push(errorLog);

      // Keep only last 10 errors
      const recentLogs = logs.slice(-10);

      await chrome.storage.local.set({ xcalibr_error_logs: recentLogs });
    } catch (storageError) {
      console.error('Failed to log error to storage:', storageError);
    }
  }

  private handleReset = (): void => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
    });
  };

  private handleResetAll = (): void => {
    appStore.reset();
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
    });
    window.location.reload();
  };

  render(): ReactNode {
    if (this.state.hasError) {
      return (
        <div className="h-full w-full flex items-center justify-center bg-dev-dark text-slate-300 p-6">
          <div className="max-w-md w-full bg-dev-card border border-red-500/30 rounded-lg p-6 space-y-4">
            {/* Error Icon */}
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-full bg-red-500/10 border border-red-500/30 flex items-center justify-center">
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 24 24"
                  strokeWidth="2"
                  stroke="currentColor"
                  className="w-6 h-6 text-red-500"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"
                  />
                </svg>
              </div>
              <div>
                <h2 className="text-lg font-bold text-white">Something went wrong</h2>
                <p className="text-sm text-slate-400">The extension encountered an error</p>
              </div>
            </div>

            {/* Error Details */}
            <div className="bg-dev-darker border border-slate-700 rounded p-3 space-y-2">
              <p className="text-sm font-mono text-red-400">
                {this.state.error?.message || 'Unknown error'}
              </p>
              {this.state.error?.stack && (
                <details className="text-xs text-slate-500">
                  <summary className="cursor-pointer hover:text-slate-400">
                    View stack trace
                  </summary>
                  <pre className="mt-2 overflow-x-auto whitespace-pre-wrap">
                    {this.state.error.stack}
                  </pre>
                </details>
              )}
            </div>

            {/* Recovery Actions */}
            <div className="space-y-2">
              <button
                onClick={this.handleReset}
                className="w-full bg-dev-green hover:bg-dev-green/90 text-black font-medium py-2 px-4 rounded transition-colors"
              >
                Try Again
              </button>
              <button
                onClick={this.handleResetAll}
                className="w-full bg-slate-700 hover:bg-slate-600 text-white font-medium py-2 px-4 rounded transition-colors"
              >
                Reset All Settings
              </button>
            </div>

            {/* Help Text */}
            <p className="text-xs text-slate-500 text-center">
              If this problem persists, try reloading the extension from chrome://extensions/
            </p>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
