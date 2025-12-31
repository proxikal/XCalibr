import React from 'react';

export type GitCommandBuilderData = {
  category?: string;
  command?: string;
  options?: Record<string, boolean | string>;
};

type Props = {
  data: GitCommandBuilderData | undefined;
  onChange: (data: GitCommandBuilderData) => void;
};

type CommandTemplate = {
  id: string;
  label: string;
  base: string;
  options: { key: string; flag: string; label: string; type: 'boolean' | 'string' }[];
};

const commandTemplates: CommandTemplate[] = [
  {
    id: 'commit',
    label: 'Commit',
    base: 'git commit',
    options: [
      { key: 'message', flag: '-m', label: 'Message', type: 'string' },
      { key: 'amend', flag: '--amend', label: 'Amend last commit', type: 'boolean' },
      { key: 'noEdit', flag: '--no-edit', label: 'No edit (amend)', type: 'boolean' },
      { key: 'all', flag: '-a', label: 'Stage all tracked', type: 'boolean' }
    ]
  },
  {
    id: 'log',
    label: 'Log',
    base: 'git log',
    options: [
      { key: 'oneline', flag: '--oneline', label: 'One line format', type: 'boolean' },
      { key: 'graph', flag: '--graph', label: 'Show graph', type: 'boolean' },
      { key: 'all', flag: '--all', label: 'All branches', type: 'boolean' },
      { key: 'count', flag: '-n', label: 'Number of commits', type: 'string' }
    ]
  },
  {
    id: 'branch',
    label: 'Branch',
    base: 'git branch',
    options: [
      { key: 'name', flag: '', label: 'Branch name', type: 'string' },
      { key: 'delete', flag: '-d', label: 'Delete branch', type: 'boolean' },
      { key: 'forceDelete', flag: '-D', label: 'Force delete', type: 'boolean' },
      { key: 'list', flag: '-a', label: 'List all', type: 'boolean' }
    ]
  },
  {
    id: 'checkout',
    label: 'Checkout',
    base: 'git checkout',
    options: [
      { key: 'branch', flag: '', label: 'Branch name', type: 'string' },
      { key: 'newBranch', flag: '-b', label: 'Create new branch', type: 'boolean' },
      { key: 'force', flag: '-f', label: 'Force checkout', type: 'boolean' }
    ]
  },
  {
    id: 'rebase',
    label: 'Rebase',
    base: 'git rebase',
    options: [
      { key: 'branch', flag: '', label: 'Target branch', type: 'string' },
      { key: 'interactive', flag: '-i', label: 'Interactive', type: 'boolean' },
      { key: 'continue', flag: '--continue', label: 'Continue', type: 'boolean' },
      { key: 'abort', flag: '--abort', label: 'Abort', type: 'boolean' }
    ]
  },
  {
    id: 'cherryPick',
    label: 'Cherry-pick',
    base: 'git cherry-pick',
    options: [
      { key: 'commit', flag: '', label: 'Commit SHA', type: 'string' },
      { key: 'noCommit', flag: '-n', label: 'No commit', type: 'boolean' },
      { key: 'continue', flag: '--continue', label: 'Continue', type: 'boolean' },
      { key: 'abort', flag: '--abort', label: 'Abort', type: 'boolean' }
    ]
  },
  {
    id: 'stash',
    label: 'Stash',
    base: 'git stash',
    options: [
      { key: 'push', flag: 'push', label: 'Push (save)', type: 'boolean' },
      { key: 'pop', flag: 'pop', label: 'Pop (apply & remove)', type: 'boolean' },
      { key: 'list', flag: 'list', label: 'List stashes', type: 'boolean' },
      { key: 'message', flag: '-m', label: 'Message', type: 'string' }
    ]
  },
  {
    id: 'reset',
    label: 'Reset',
    base: 'git reset',
    options: [
      { key: 'commit', flag: '', label: 'Commit/ref', type: 'string' },
      { key: 'soft', flag: '--soft', label: 'Soft (keep staged)', type: 'boolean' },
      { key: 'mixed', flag: '--mixed', label: 'Mixed (unstage)', type: 'boolean' },
      { key: 'hard', flag: '--hard', label: 'Hard (discard all)', type: 'boolean' }
    ]
  }
];

const GitCommandBuilder: React.FC<Props> = ({ data, onChange }) => {
  const category = data?.category ?? 'commit';
  const options = data?.options ?? {};

  const template = commandTemplates.find((t) => t.id === category) ?? commandTemplates[0];

  const buildCommand = () => {
    let cmd = template.base;
    const parts: string[] = [];

    template.options.forEach((opt) => {
      const value = options[opt.key];
      if (opt.type === 'boolean' && value === true) {
        if (opt.flag) parts.push(opt.flag);
      } else if (opt.type === 'string' && typeof value === 'string' && value.trim()) {
        if (opt.flag) {
          if (opt.flag === '-m') {
            parts.push(`${opt.flag} "${value}"`);
          } else if (opt.flag === '-n' || opt.flag === '') {
            if (opt.flag) parts.push(`${opt.flag} ${value}`);
            else parts.push(value);
          } else {
            parts.push(`${opt.flag} ${value}`);
          }
        } else {
          parts.push(value);
        }
      }
    });

    if (parts.length > 0) {
      cmd += ' ' + parts.join(' ');
    }

    onChange({ ...data, command: cmd });
  };

  const handleCopy = () => {
    if (data?.command) {
      navigator.clipboard.writeText(data.command);
    }
  };

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs text-gray-400 mb-1">Command Category</label>
        <select
          value={category}
          onChange={(e) => onChange({ ...data, category: e.target.value, options: {} })}
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
        >
          {commandTemplates.map((t) => (
            <option key={t.id} value={t.id}>
              {t.label}
            </option>
          ))}
        </select>
      </div>

      <div className="space-y-2">
        <div className="text-xs text-gray-400">Options</div>
        {template.options.map((opt) => (
          <div key={opt.key}>
            {opt.type === 'boolean' ? (
              <label className="flex items-center gap-2 text-sm text-gray-300">
                <input
                  type="checkbox"
                  checked={options[opt.key] === true}
                  onChange={(e) =>
                    onChange({ ...data, options: { ...options, [opt.key]: e.target.checked } })
                  }
                  className="rounded bg-gray-700 border-gray-600"
                />
                <span className="font-mono text-xs text-blue-400">{opt.flag}</span>
                {opt.label}
              </label>
            ) : (
              <div>
                <label className="block text-xs text-gray-400 mb-1">
                  {opt.label} {opt.flag && <span className="font-mono text-blue-400">({opt.flag})</span>}
                </label>
                <input
                  type="text"
                  value={(options[opt.key] as string) || ''}
                  onChange={(e) =>
                    onChange({ ...data, options: { ...options, [opt.key]: e.target.value } })
                  }
                  placeholder={`Enter ${opt.label.toLowerCase()}...`}
                  className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-sm"
                />
              </div>
            )}
          </div>
        ))}
      </div>

      <button
        onClick={buildCommand}
        className="w-full py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-sm"
      >
        Build Command
      </button>

      {data?.command && (
        <div
          onClick={handleCopy}
          className="bg-[#0d0d1a] border border-gray-700 rounded p-3 cursor-pointer hover:border-blue-500"
          title="Click to copy"
        >
          <div className="text-xs text-gray-400 mb-1">Generated Command</div>
          <div className="font-mono text-green-400 text-sm break-all">{data.command}</div>
        </div>
      )}
    </div>
  );
};

export class GitCommandBuilderTool {
  static Component = GitCommandBuilder;
}
