import React from 'react';

export type TextDiffData = {
  text1?: string;
  text2?: string;
  diffResult?: DiffChunk[];
};

type DiffChunk = {
  type: 'equal' | 'added' | 'removed';
  value: string;
};

type Props = {
  data: TextDiffData | undefined;
  onChange: (data: TextDiffData) => void;
};

const computeDiff = (text1: string, text2: string): DiffChunk[] => {
  const lines1 = text1.split('\n');
  const lines2 = text2.split('\n');
  const result: DiffChunk[] = [];

  // Simple line-by-line diff using LCS approach
  const lcs = (a: string[], b: string[]): string[][] => {
    const m = a.length;
    const n = b.length;
    const dp: number[][] = Array(m + 1).fill(null).map(() => Array(n + 1).fill(0));

    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        if (a[i - 1] === b[j - 1]) {
          dp[i][j] = dp[i - 1][j - 1] + 1;
        } else {
          dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
        }
      }
    }

    // Backtrack to find LCS
    const common: string[] = [];
    let i = m, j = n;
    while (i > 0 && j > 0) {
      if (a[i - 1] === b[j - 1]) {
        common.unshift(a[i - 1]);
        i--;
        j--;
      } else if (dp[i - 1][j] > dp[i][j - 1]) {
        i--;
      } else {
        j--;
      }
    }

    return [a, b, common];
  };

  const [, , common] = lcs(lines1, lines2);

  let i = 0, j = 0, k = 0;

  while (i < lines1.length || j < lines2.length) {
    if (k < common.length && i < lines1.length && lines1[i] === common[k]) {
      if (j < lines2.length && lines2[j] === common[k]) {
        result.push({ type: 'equal', value: common[k] });
        i++;
        j++;
        k++;
      } else {
        result.push({ type: 'added', value: lines2[j] });
        j++;
      }
    } else if (i < lines1.length && (k >= common.length || lines1[i] !== common[k])) {
      result.push({ type: 'removed', value: lines1[i] });
      i++;
    } else if (j < lines2.length) {
      result.push({ type: 'added', value: lines2[j] });
      j++;
    }
  }

  return result;
};

const TextDiff: React.FC<Props> = ({ data, onChange }) => {
  const text1 = data?.text1 ?? '';
  const text2 = data?.text2 ?? '';
  const diffResult = data?.diffResult ?? [];

  const handleCompare = () => {
    const result = computeDiff(text1, text2);
    onChange({ ...data, diffResult: result });
  };

  const getChunkStyle = (type: string) => {
    switch (type) {
      case 'added':
        return 'bg-green-900/50 text-green-300';
      case 'removed':
        return 'bg-red-900/50 text-red-300 line-through';
      default:
        return 'text-gray-300';
    }
  };

  const getChunkPrefix = (type: string) => {
    switch (type) {
      case 'added': return '+ ';
      case 'removed': return '- ';
      default: return '  ';
    }
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Original Text</label>
          <textarea
            value={text1}
            onChange={(e) => onChange({ ...data, text1: e.target.value, diffResult: [] })}
            placeholder="Enter original text..."
            rows={8}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-xs resize-none"
          />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Modified Text</label>
          <textarea
            value={text2}
            onChange={(e) => onChange({ ...data, text2: e.target.value, diffResult: [] })}
            placeholder="Enter modified text..."
            rows={8}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-xs resize-none"
          />
        </div>
      </div>

      <button
        onClick={handleCompare}
        disabled={!text1 && !text2}
        className="w-full py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white rounded text-sm"
      >
        Compare
      </button>

      {diffResult.length > 0 && (
        <div>
          <label className="block text-xs text-gray-400 mb-1">Diff Result</label>
          <div className="bg-[#1a1a2e] border border-gray-700 rounded p-3 font-mono text-xs max-h-64 overflow-y-auto">
            {diffResult.map((chunk, idx) => (
              <div key={idx} className={`${getChunkStyle(chunk.type)} px-2 py-0.5`}>
                {getChunkPrefix(chunk.type)}{chunk.value || ' '}
              </div>
            ))}
          </div>
          <div className="flex gap-4 mt-2 text-xs">
            <span className="text-green-400">+ Added</span>
            <span className="text-red-400">- Removed</span>
            <span className="text-gray-400">Unchanged</span>
          </div>
        </div>
      )}
    </div>
  );
};

export class TextDiffTool {
  static Component = TextDiff;
}
