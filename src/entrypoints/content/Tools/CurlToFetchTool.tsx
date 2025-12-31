import React from 'react';

export type CurlToFetchData = {
  input?: string;
  output?: string;
  useAsync?: boolean;
  error?: string;
};

type Props = {
  data: CurlToFetchData | undefined;
  onChange: (data: CurlToFetchData) => void;
};

const parseCurl = (curlCmd: string): { url: string; method: string; headers: Record<string, string>; body?: string } => {
  const result: { url: string; method: string; headers: Record<string, string>; body?: string } = {
    url: '',
    method: 'GET',
    headers: {}
  };

  // Remove 'curl' prefix and normalize whitespace
  let cmd = curlCmd.replace(/^curl\s+/i, '').trim();

  // Extract URL (first unquoted URL or quoted string that looks like URL)
  const urlMatch = cmd.match(/['"]?(https?:\/\/[^\s'"]+)['"]?/);
  if (urlMatch) {
    result.url = urlMatch[1];
  }

  // Extract method (-X or --request)
  const methodMatch = cmd.match(/-X\s+['"]?(\w+)['"]?|--request\s+['"]?(\w+)['"]?/);
  if (methodMatch) {
    result.method = (methodMatch[1] || methodMatch[2]).toUpperCase();
  }

  // Extract headers (-H or --header)
  const headerRegex = /-H\s+['"]([^'"]+)['"]|--header\s+['"]([^'"]+)['"]/g;
  let headerMatch;
  while ((headerMatch = headerRegex.exec(cmd)) !== null) {
    const header = headerMatch[1] || headerMatch[2];
    const [key, ...valueParts] = header.split(':');
    if (key && valueParts.length > 0) {
      result.headers[key.trim()] = valueParts.join(':').trim();
    }
  }

  // Extract body (-d or --data or --data-raw)
  const bodyMatch = cmd.match(/-d\s+['"]([^'"]+)['"]|--data\s+['"]([^'"]+)['"]|--data-raw\s+['"]([^'"]+)['"]/);
  if (bodyMatch) {
    result.body = bodyMatch[1] || bodyMatch[2] || bodyMatch[3];
    if (result.method === 'GET') {
      result.method = 'POST';
    }
  }

  return result;
};

const generateFetch = (parsed: ReturnType<typeof parseCurl>, useAsync: boolean): string => {
  const lines: string[] = [];

  if (useAsync) {
    lines.push('const response = await fetch(');
  } else {
    lines.push('fetch(');
  }

  lines.push(`  "${parsed.url}",`);
  lines.push('  {');
  lines.push(`    method: "${parsed.method}",`);

  if (Object.keys(parsed.headers).length > 0) {
    lines.push('    headers: {');
    for (const [key, value] of Object.entries(parsed.headers)) {
      lines.push(`      "${key}": "${value}",`);
    }
    lines.push('    },');
  }

  if (parsed.body) {
    const isJson = parsed.headers['Content-Type']?.includes('application/json') || parsed.body.startsWith('{');
    if (isJson) {
      lines.push(`    body: JSON.stringify(${parsed.body}),`);
    } else {
      lines.push(`    body: "${parsed.body.replace(/"/g, '\\"')}",`);
    }
  }

  lines.push('  }');
  lines.push(');');

  if (useAsync) {
    lines.push('');
    lines.push('const data = await response.json();');
  } else {
    lines.push('');
    lines.push('.then(response => response.json())');
    lines.push('.then(data => console.log(data))');
    lines.push('.catch(error => console.error(error));');
  }

  return lines.join('\n');
};

const CurlToFetch: React.FC<Props> = ({ data, onChange }) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const useAsync = data?.useAsync ?? true;
  const error = data?.error ?? '';

  const handleConvert = () => {
    try {
      if (!input.trim()) {
        throw new Error('Please enter a cURL command');
      }

      const parsed = parseCurl(input);
      if (!parsed.url) {
        throw new Error('Could not find a valid URL in the cURL command');
      }

      const fetchCode = generateFetch(parsed, useAsync);
      onChange({ ...data, output: fetchCode, error: '' });
    } catch (e) {
      onChange({
        ...data,
        error: e instanceof Error ? e.message : 'Failed to parse cURL command'
      });
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(output);
  };

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs text-gray-400 mb-1">cURL Command</label>
        <textarea
          value={input}
          onChange={(e) => onChange({ ...data, input: e.target.value })}
          placeholder={`curl -X POST "https://api.example.com/data" \\
  -H "Content-Type: application/json" \\
  -d '{"key": "value"}'`}
          className="w-full h-28 px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-xs resize-none"
        />
      </div>

      <label className="flex items-center gap-2 text-sm text-gray-300">
        <input
          type="checkbox"
          checked={useAsync}
          onChange={(e) => onChange({ ...data, useAsync: e.target.checked })}
          className="rounded bg-gray-700 border-gray-600"
        />
        Use async/await syntax
      </label>

      <button
        onClick={handleConvert}
        disabled={!input.trim()}
        className="w-full py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white rounded text-sm"
      >
        Convert to JavaScript Fetch
      </button>

      {error && (
        <div className="text-red-400 text-xs p-2 bg-red-900/20 rounded">
          {error}
        </div>
      )}

      {output && !error && (
        <div className="space-y-2">
          <div className="flex justify-between items-center">
            <span className="text-xs text-gray-400">JavaScript Fetch</span>
            <button onClick={handleCopy} className="text-xs text-blue-400 hover:text-blue-300">
              Copy
            </button>
          </div>
          <textarea
            readOnly
            value={output}
            className="w-full h-40 px-3 py-2 bg-[#0d0d1a] border border-gray-700 rounded text-green-400 font-mono text-xs resize-none"
          />
        </div>
      )}
    </div>
  );
};

export class CurlToFetchTool {
  static Component = CurlToFetch;
}
