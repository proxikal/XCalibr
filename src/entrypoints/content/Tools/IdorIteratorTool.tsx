import React, { useState } from 'react';

export type IdorResult = {
  id: number | string;
  status: number;
  size?: number;
  url: string;
};

export type IdorIteratorData = {
  urlPattern?: string;
  startId?: number;
  endId?: number;
  results?: IdorResult[];
  isRunning?: boolean;
  progress?: number;
  error?: string;
};

type Props = {
  data: IdorIteratorData | undefined;
  onChange: (data: IdorIteratorData) => void;
};

const IdorIterator: React.FC<Props> = ({ data, onChange }) => {
  const urlPattern = data?.urlPattern ?? '';
  const startId = data?.startId ?? 1;
  const endId = data?.endId ?? 10;
  const results = data?.results ?? [];
  const isRunning = data?.isRunning ?? false;
  const progress = data?.progress ?? 0;
  const error = data?.error ?? '';
  const [abortController, setAbortController] = useState<AbortController | null>(null);

  const handleScan = async () => {
    if (!urlPattern.includes('{ID}')) {
      onChange({ ...data, error: 'URL must contain {ID} placeholder' });
      return;
    }

    const controller = new AbortController();
    setAbortController(controller);
    onChange({ ...data, isRunning: true, results: [], progress: 0, error: '' });

    const foundResults: IdorResult[] = [];
    const total = endId - startId + 1;

    for (let id = startId; id <= endId; id++) {
      if (controller.signal.aborted) break;

      const url = urlPattern.replace('{ID}', id.toString());

      try {
        const response = await chrome.runtime.sendMessage({
          type: 'xcalibr-http-request',
          payload: { url, method: 'GET' }
        });

        if (response?.status === 200 || response?.status === 201) {
          foundResults.push({
            id,
            status: response.status,
            size: response.body?.length || 0,
            url
          });
        }

        onChange({
          ...data,
          isRunning: true,
          results: [...foundResults],
          progress: Math.round(((id - startId + 1) / total) * 100)
        });

        // Rate limiting - 100ms between requests
        await new Promise(r => setTimeout(r, 100));
      } catch {
        // Skip failed requests
      }
    }

    onChange({
      ...data,
      isRunning: false,
      results: foundResults,
      progress: 100
    });
    setAbortController(null);
  };

  const handleStop = () => {
    abortController?.abort();
    onChange({ ...data, isRunning: false });
  };

  const handleClear = () => {
    onChange({ ...data, results: [], progress: 0 });
  };

  const successfulResults = results.filter(r => r.status >= 200 && r.status < 300);

  return (
    <div className="space-y-4">
      <div className="text-xs text-gray-400">
        Test for Insecure Direct Object References by iterating through IDs.
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">URL Pattern (use {'{ID}'} as placeholder)</label>
        <input
          type="text"
          value={urlPattern}
          onChange={(e) => onChange({ ...data, urlPattern: e.target.value })}
          placeholder="https://api.example.com/user/{ID}"
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-sm"
        />
      </div>

      <div className="grid grid-cols-2 gap-2">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Start ID</label>
          <input
            type="number"
            value={startId}
            onChange={(e) => onChange({ ...data, startId: parseInt(e.target.value) || 1 })}
            min={0}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">End ID</label>
          <input
            type="number"
            value={endId}
            onChange={(e) => onChange({ ...data, endId: parseInt(e.target.value) || 10 })}
            min={startId}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          />
        </div>
      </div>

      {error && (
        <div className="text-red-400 text-xs bg-red-900/20 p-2 rounded">{error}</div>
      )}

      <div className="flex gap-2">
        {isRunning ? (
          <button
            onClick={handleStop}
            className="flex-1 py-2 bg-yellow-600 hover:bg-yellow-500 text-white rounded text-sm"
          >
            Stop ({progress}%)
          </button>
        ) : (
          <button
            onClick={handleScan}
            disabled={!urlPattern.includes('{ID}')}
            className="flex-1 py-2 bg-red-600 hover:bg-red-500 disabled:bg-gray-600 text-white rounded text-sm"
          >
            Start IDOR Scan
          </button>
        )}
        <button
          onClick={handleClear}
          disabled={isRunning || results.length === 0}
          className="py-2 px-4 bg-gray-600 hover:bg-gray-500 disabled:bg-gray-700 text-white rounded text-sm"
        >
          Clear
        </button>
      </div>

      {isRunning && (
        <div className="w-full bg-gray-700 rounded-full h-2">
          <div
            className="bg-red-500 h-2 rounded-full transition-all"
            style={{ width: `${progress}%` }}
          />
        </div>
      )}

      {successfulResults.length > 0 && (
        <div className="space-y-2">
          <div className="flex justify-between items-center">
            <span className="text-xs text-green-400">
              Found {successfulResults.length} accessible resources
            </span>
          </div>
          <div className="max-h-40 overflow-y-auto space-y-1">
            {successfulResults.map((result, i) => (
              <div key={i} className="flex justify-between items-center text-xs bg-green-900/20 px-2 py-1 rounded">
                <span className="text-green-400 font-mono">ID: {result.id}</span>
                <span className="text-gray-400">{result.status} ({result.size} bytes)</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="text-xs text-gray-500">
        <strong>Warning:</strong> Only use on authorized targets. Rate limited to 10 req/sec.
      </div>
    </div>
  );
};

export class IdorIteratorTool {
  static Component = IdorIterator;
}
