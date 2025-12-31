import React, { useCallback } from 'react';
import type { DockerfileLinterData } from './tool-types';

const lintDockerfile = (content: string): string[] => {
  const warnings: string[] = [];
  const lines = content.split('\n');

  lines.forEach((line, i) => {
    const trimmed = line.trim();
    const lineNum = i + 1;

    if (/^FROM\s+\S+:latest/i.test(trimmed)) {
      warnings.push(`Line ${lineNum}: Avoid using ':latest' tag. Pin to specific version.`);
    }

    if (/^ADD\s+/i.test(trimmed) && !trimmed.includes('.tar') && !trimmed.includes('http')) {
      warnings.push(`Line ${lineNum}: Use COPY instead of ADD for local files.`);
    }

    if (/^RUN\s+apt-get\s+install/i.test(trimmed) && !trimmed.includes('-y')) {
      warnings.push(`Line ${lineNum}: Add '-y' flag to apt-get install for non-interactive.`);
    }

    if (/^RUN\s+apt-get\s+update/i.test(trimmed) && !lines[i + 1]?.trim().toLowerCase().includes('apt-get install')) {
      warnings.push(`Line ${lineNum}: Combine apt-get update with install in same RUN.`);
    }

    if (/^RUN\s+pip\s+install/i.test(trimmed) && !trimmed.includes('--no-cache-dir')) {
      warnings.push(`Line ${lineNum}: Consider using --no-cache-dir with pip install.`);
    }

    if (/^RUN\s+cd\s+/i.test(trimmed)) {
      warnings.push(`Line ${lineNum}: Use WORKDIR instead of 'cd' command.`);
    }

    if (/^EXPOSE\s+\d+$/i.test(trimmed) && !content.includes('ENV')) {
      // Just a hint
    }
  });

  if (!content.toLowerCase().includes('user ') && content.toLowerCase().includes('from')) {
    warnings.push('Consider adding a USER instruction to avoid running as root.');
  }

  if ((content.match(/^RUN\s+/gim) || []).length > 5) {
    warnings.push('Consider combining multiple RUN instructions to reduce layers.');
  }

  return warnings;
};

type Props = {
  data: DockerfileLinterData | undefined;
  onChange: (next: DockerfileLinterData) => void;
};

const DockerfileLinterToolComponent = ({ data, onChange }: Props) => {
  const input = data?.input ?? '';
  const warnings = data?.warnings ?? [];

  const handleLint = useCallback(() => {
    const result = lintDockerfile(input);
    onChange({ ...data, warnings: result });
  }, [input, data, onChange]);

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Dockerfile Linter</div>

      <textarea
        value={input}
        onChange={(e) => onChange({ ...data, input: e.target.value, warnings: [] })}
        rows={8}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-emerald-500 font-mono"
        placeholder="FROM node:18-alpine
WORKDIR /app
COPY . .
RUN npm install
CMD [&quot;npm&quot;, &quot;start&quot;]"
      />

      <button
        type="button"
        onClick={handleLint}
        className="w-full rounded bg-emerald-600 text-white text-xs py-2 hover:bg-emerald-500"
      >
        Lint Dockerfile
      </button>

      {warnings.length > 0 && (
        <div className="space-y-1">
          <div className="text-[11px] text-yellow-400">Warnings ({warnings.length})</div>
          <div className="bg-slate-800 rounded p-2 max-h-32 overflow-y-auto">
            {warnings.map((w, i) => (
              <div key={i} className="text-[10px] text-yellow-300 py-0.5">⚠️ {w}</div>
            ))}
          </div>
        </div>
      )}

      {input && warnings.length === 0 && (
        <div className="bg-emerald-900/30 border border-emerald-700 rounded p-2 text-[10px] text-emerald-300">
          ✓ No issues found
        </div>
      )}

      <div className="text-[10px] text-slate-500">
        Checks for common Dockerfile best practices and anti-patterns.
      </div>
    </div>
  );
};

export class DockerfileLinterTool {
  static Component = DockerfileLinterToolComponent;
}
