import React from 'react';

export type GitIgnoreGeneratorData = {
  selectedTemplates?: string[];
  output?: string;
  customRules?: string;
};

type Props = {
  data: GitIgnoreGeneratorData | undefined;
  onChange: (data: GitIgnoreGeneratorData) => void;
};

const templates: Record<string, string[]> = {
  Node: ['node_modules/', 'npm-debug.log', 'yarn-error.log', '.npm', '.yarn', 'dist/', 'build/'],
  Python: ['__pycache__/', '*.py[cod]', '*$py.class', '.Python', 'venv/', '.env', '*.egg-info/'],
  Java: ['*.class', '*.jar', '*.war', 'target/', '.gradle/', 'build/', '.idea/'],
  macOS: ['.DS_Store', '.AppleDouble', '.LSOverride', '._*', '.Spotlight-V100', '.Trashes'],
  Windows: ['Thumbs.db', 'ehthumbs.db', 'Desktop.ini', '$RECYCLE.BIN/', '*.lnk'],
  Linux: ['*~', '.fuse_hidden*', '.directory', '.Trash-*', '.nfs*'],
  VSCode: ['.vscode/', '*.code-workspace', '.history/'],
  JetBrains: ['.idea/', '*.iml', '*.ipr', '*.iws', 'out/'],
  React: ['node_modules/', 'build/', '.env.local', '.env.*.local', 'npm-debug.log*'],
  NextJS: ['.next/', 'out/', 'node_modules/', '.env*.local', 'npm-debug.log*'],
  Rust: ['target/', 'Cargo.lock', '**/*.rs.bk'],
  Go: ['*.exe', '*.exe~', '*.dll', '*.so', '*.dylib', 'vendor/', 'bin/'],
  Ruby: ['*.gem', '*.rbc', '/.config', '/coverage/', '/InstalledFiles', '/pkg/', '/vendor/bundle'],
  Logs: ['*.log', 'logs/', '*.log.*', 'npm-debug.log*', 'yarn-debug.log*'],
  Environment: ['.env', '.env.local', '.env.*.local', '*.env', 'config.local.js']
};

const GitIgnoreGenerator: React.FC<Props> = ({ data, onChange }) => {
  const selectedTemplates = data?.selectedTemplates ?? [];
  const output = data?.output ?? '';
  const customRules = data?.customRules ?? '';

  const toggleTemplate = (name: string) => {
    const newSelection = selectedTemplates.includes(name)
      ? selectedTemplates.filter((t) => t !== name)
      : [...selectedTemplates, name];
    onChange({ ...data, selectedTemplates: newSelection });
  };

  const handleGenerate = () => {
    const lines: string[] = [];

    selectedTemplates.forEach((templateName) => {
      const rules = templates[templateName];
      if (rules) {
        lines.push(`# ${templateName}`);
        lines.push(...rules);
        lines.push('');
      }
    });

    if (customRules.trim()) {
      lines.push('# Custom Rules');
      lines.push(...customRules.split('\n').filter((l) => l.trim()));
      lines.push('');
    }

    onChange({ ...data, output: lines.join('\n') });
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(output);
  };

  const handleDownload = () => {
    const blob = new Blob([output], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = '.gitignore';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      <div>
        <div className="text-xs text-gray-400 mb-2">Select Templates</div>
        <div className="grid grid-cols-3 gap-1 max-h-40 overflow-y-auto">
          {Object.keys(templates).map((name) => (
            <button
              key={name}
              onClick={() => toggleTemplate(name)}
              className={`py-1.5 px-2 rounded text-xs ${
                selectedTemplates.includes(name)
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
              }`}
            >
              {name}
            </button>
          ))}
        </div>
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Custom Rules (one per line)</label>
        <textarea
          value={customRules}
          onChange={(e) => onChange({ ...data, customRules: e.target.value })}
          placeholder="*.secret&#10;my-folder/"
          className="w-full h-16 px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-xs resize-none"
        />
      </div>

      <button
        onClick={handleGenerate}
        disabled={selectedTemplates.length === 0 && !customRules.trim()}
        className="w-full py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white rounded text-sm"
      >
        Generate .gitignore
      </button>

      {output && (
        <div className="space-y-2">
          <div className="flex justify-between items-center">
            <span className="text-xs text-gray-400">Generated .gitignore</span>
            <div className="flex gap-2">
              <button onClick={handleCopy} className="text-xs text-blue-400 hover:text-blue-300">
                Copy
              </button>
              <button onClick={handleDownload} className="text-xs text-green-400 hover:text-green-300">
                Download
              </button>
            </div>
          </div>
          <textarea
            readOnly
            value={output}
            className="w-full h-48 px-3 py-2 bg-[#0d0d1a] border border-gray-700 rounded text-gray-300 font-mono text-xs resize-none"
          />
        </div>
      )}
    </div>
  );
};

export class GitIgnoreGeneratorTool {
  static Component = GitIgnoreGenerator;
}
