/**
 * JSON Formatter Tool
 * Prettify and validate JSON with persistent state
 */

import React, { useState } from 'react';
import { useJSONFormatter } from '@/hooks/useAppStore';

export const JSONFormatter: React.FC = () => {
  const {
    jsonFormatterState,
    setInputJSON,
    setFormattedJSON,
    setIndentSize,
    setSortKeys,
    setError,
    clearAll,
  } = useJSONFormatter();

  const [copied, setCopied] = useState(false);

  const formatJSON = () => {
    try {
      // Parse JSON
      const parsed = JSON.parse(jsonFormatterState.inputJSON);

      // Sort keys if enabled
      const processedData = jsonFormatterState.sortKeys
        ? sortObjectKeys(parsed)
        : parsed;

      // Format with specified indent
      const formatted = JSON.stringify(
        processedData,
        null,
        jsonFormatterState.indentSize
      );

      setFormattedJSON(formatted);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid JSON');
      setFormattedJSON('');
    }
  };

  const sortObjectKeys = (obj: any): any => {
    if (Array.isArray(obj)) {
      return obj.map(sortObjectKeys);
    } else if (obj !== null && typeof obj === 'object') {
      const sorted: Record<string, any> = {};
      Object.keys(obj)
        .sort()
        .forEach((key) => {
          sorted[key] = sortObjectKeys(obj[key]);
        });
      return sorted;
    }
    return obj;
  };

  const minifyJSON = () => {
    try {
      const parsed = JSON.parse(jsonFormatterState.inputJSON);
      const minified = JSON.stringify(parsed);
      setFormattedJSON(minified);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid JSON');
      setFormattedJSON('');
    }
  };

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(jsonFormatterState.formattedJSON);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <main className="flex-1 overflow-y-auto p-5 space-y-6 custom-scrollbar relative">
        {/* Background Gradient */}
        <div className="fixed top-0 right-0 -mr-20 -mt-20 w-64 h-64 bg-dev-green/5 blur-3xl rounded-full pointer-events-none"></div>

        {/* Configuration Section */}
        <section className="space-y-3 relative z-0">
          <h2 className="text-xs uppercase tracking-wider text-slate-500 font-semibold mb-2">
            Configuration
          </h2>

          <div className="grid grid-cols-2 gap-3">
            {/* Indent Size */}
            <div className="space-y-1">
              <label className="block text-sm font-medium text-slate-300">
                Indent Size
              </label>
              <select
                value={jsonFormatterState.indentSize}
                onChange={(e) => setIndentSize(Number(e.target.value))}
                className="w-full bg-dev-card border border-slate-700 rounded-md px-3 py-2 text-sm text-white focus:outline-none focus:border-dev-green/50 focus:ring-1 focus:ring-dev-green/50 transition-all"
              >
                <option value={2}>2 spaces</option>
                <option value={4}>4 spaces</option>
                <option value={8}>8 spaces</option>
              </select>
            </div>

            {/* Sort Keys Checkbox */}
            <div className="space-y-1">
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Options
              </label>
              <label className="checkbox-wrapper flex items-center gap-3 cursor-pointer group">
                <input
                  type="checkbox"
                  checked={jsonFormatterState.sortKeys}
                  onChange={(e) => setSortKeys(e.target.checked)}
                  className="hidden"
                />
                <div
                  className={`w-5 h-5 rounded border flex items-center justify-center transition-colors group-hover:border-slate-500 ${
                    jsonFormatterState.sortKeys
                      ? 'bg-dev-green border-dev-green'
                      : 'border-slate-600 bg-slate-800'
                  }`}
                >
                  <svg
                    className={`w-3.5 h-3.5 text-black transition-opacity ${
                      jsonFormatterState.sortKeys ? 'opacity-100' : 'opacity-0'
                    }`}
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth="3"
                      d="M5 13l4 4L19 7"
                    />
                  </svg>
                </div>
                <span className="text-sm text-slate-300 group-hover:text-white transition-colors">
                  Sort keys alphabetically
                </span>
              </label>
            </div>
          </div>
        </section>

        <div className="h-px bg-slate-800"></div>

        {/* Input Section */}
        <section className="space-y-2 relative z-0">
          <div className="flex items-center justify-between">
            <label className="block text-sm font-medium text-slate-300">
              JSON Input
            </label>
            {jsonFormatterState.inputJSON && (
              <button
                onClick={() => setInputJSON('')}
                className="text-xs text-slate-500 hover:text-dev-green transition-colors"
              >
                Clear input
              </button>
            )}
          </div>
          <textarea
            value={jsonFormatterState.inputJSON}
            onChange={(e) => setInputJSON(e.target.value)}
            placeholder='{"name": "example", "value": 123}'
            className="w-full h-32 bg-dev-card border border-slate-700 rounded-md px-3 py-2 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-dev-green/50 focus:ring-1 focus:ring-dev-green/50 transition-all font-mono resize-none"
          />
        </section>

        {/* Error Display */}
        {jsonFormatterState.error && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3">
            <div className="flex items-start gap-2">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
                strokeWidth="2"
                stroke="currentColor"
                className="w-5 h-5 text-red-500 shrink-0 mt-0.5"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"
                />
              </svg>
              <div>
                <p className="text-sm font-medium text-red-400">Invalid JSON</p>
                <p className="text-xs text-red-300/80 mt-1">
                  {jsonFormatterState.error}
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Output Section */}
        {jsonFormatterState.formattedJSON && (
          <section className="space-y-2 relative z-0">
            <div className="flex items-center justify-between">
              <label className="block text-sm font-medium text-slate-300">
                Formatted JSON
              </label>
              <button
                onClick={copyToClipboard}
                className="flex items-center gap-1.5 text-xs text-slate-500 hover:text-dev-green transition-colors"
              >
                {copied ? (
                  <>
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      viewBox="0 0 24 24"
                      fill="currentColor"
                      className="w-3.5 h-3.5 text-dev-green"
                    >
                      <path
                        fillRule="evenodd"
                        d="M19.916 4.626a.75.75 0 01.208 1.04l-9 13.5a.75.75 0 01-1.154.114l-6-6a.75.75 0 011.06-1.06l5.353 5.353 8.493-12.739a.75.75 0 011.04-.208z"
                        clipRule="evenodd"
                      />
                    </svg>
                    Copied!
                  </>
                ) : (
                  <>
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      fill="none"
                      viewBox="0 0 24 24"
                      strokeWidth="2"
                      stroke="currentColor"
                      className="w-3.5 h-3.5"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        d="M15.666 3.888A2.25 2.25 0 0013.5 2.25h-3c-1.03 0-1.9.693-2.166 1.638m7.332 0c.055.194.084.4.084.612v0a.75.75 0 01-.75.75H9a.75.75 0 01-.75-.75v0c0-.212.03-.418.084-.612m7.332 0c.646.049 1.288.11 1.927.184 1.1.128 1.907 1.077 1.907 2.185V19.5a2.25 2.25 0 01-2.25 2.25H6.75A2.25 2.25 0 014.5 19.5V6.257c0-1.108.806-2.057 1.907-2.185a48.208 48.208 0 011.927-.184"
                      />
                    </svg>
                    Copy
                  </>
                )}
              </button>
            </div>
            <pre className="w-full h-48 bg-dev-darker border border-slate-700 rounded-md px-3 py-2 text-sm text-dev-green overflow-auto font-mono custom-scrollbar">
              {jsonFormatterState.formattedJSON}
            </pre>
          </section>
        )}

        {/* Action Buttons */}
        <section className="pt-2 flex gap-3 relative z-0">
          <button
            onClick={clearAll}
            className="flex-1 bg-transparent border border-slate-600 text-slate-300 hover:text-white hover:border-slate-400 py-2 rounded-md text-sm font-medium transition-colors"
          >
            Clear All
          </button>
          <button
            onClick={minifyJSON}
            disabled={!jsonFormatterState.inputJSON}
            className="flex-1 bg-slate-700 text-white hover:bg-slate-600 disabled:bg-slate-800 disabled:text-slate-600 disabled:cursor-not-allowed py-2 rounded-md text-sm font-medium transition-colors"
          >
            Minify
          </button>
          <button
            onClick={formatJSON}
            disabled={!jsonFormatterState.inputJSON}
            className="flex-1 bg-dev-green text-black hover:bg-[#00ff00] disabled:bg-slate-800 disabled:text-slate-600 disabled:cursor-not-allowed py-2 rounded-md text-sm font-bold shadow-[0_0_15px_rgba(0,230,0,0.3)] hover:shadow-[0_0_20px_rgba(0,230,0,0.5)] transition-all"
          >
            Format
          </button>
        </section>
      </main>
    </div>
  );
};
