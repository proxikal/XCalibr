/**
 * ToolView Component
 * Wrapper for individual tool views with navigation
 */

import React from 'react';
import { useNavigation } from '@/hooks/useAppStore';
import { JSONFormatter } from '@/components/tools/JSONFormatter';
import { RegexTester } from '@/components/tools/RegexTester';
import { tools } from '@/data/tools';

export const ToolView: React.FC = () => {
  const { activeToolId, closeTool } = useNavigation();

  if (!activeToolId) {
    return null;
  }

  const tool = tools.find((t) => t.id === activeToolId);

  if (!tool) {
    return null;
  }

  // Render appropriate tool component based on ID
  const renderTool = () => {
    switch (activeToolId) {
      case 'json-formatter':
        return <JSONFormatter />;
      case 'regex-tester':
        return <RegexTester />;
      // Future tools can be added here
      default:
        return (
          <div className="flex items-center justify-center h-full">
            <div className="text-center">
              <p className="text-slate-400 mb-2">
                Tool "{tool.name}" is not implemented yet
              </p>
              <p className="text-xs text-slate-600">Coming soon!</p>
            </div>
          </div>
        );
    }
  };

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Tool Navigation Bar */}
      <nav className="flex items-center px-4 py-3 bg-dev-dark border-b border-slate-800/50 shrink-0 gap-3">
        <button
          onClick={closeTool}
          className="flex items-center gap-1.5 text-slate-400 hover:text-dev-green transition-colors group"
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
            strokeWidth="2.5"
            stroke="currentColor"
            className="w-4 h-4"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M15.75 19.5L8.25 12l7.5-7.5"
            />
          </svg>
          <span className="text-xs font-bold uppercase tracking-widest">
            Back
          </span>
        </button>
        <div className="h-4 w-px bg-slate-700 mx-1"></div>
        <h2 className="text-sm font-semibold text-slate-200">{tool.name}</h2>
      </nav>

      {/* Tool Content */}
      {renderTool()}
    </div>
  );
};
