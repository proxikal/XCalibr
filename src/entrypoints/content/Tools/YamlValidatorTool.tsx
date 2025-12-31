import React, { useCallback } from 'react';
import type { YamlValidatorData } from './tool-types';

// Simple YAML validator - checks basic syntax
const validateYaml = (input: string): { valid: boolean; error?: string } => {
  if (!input.trim()) return { valid: false, error: 'Empty input' };

  const lines = input.split('\n');
  let prevIndent = 0;
  let inMultiline = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // Skip empty lines and comments
    if (!line.trim() || line.trim().startsWith('#')) continue;

    // Check for tabs (YAML uses spaces)
    if (line.includes('\t')) {
      return { valid: false, error: `Line ${lineNum}: Tabs not allowed, use spaces` };
    }

    // Calculate indentation
    const indent = line.length - line.trimStart().length;

    // Check for invalid indentation increase (should be consistent, usually 2)
    if (indent > prevIndent + 4 && !inMultiline) {
      return { valid: false, error: `Line ${lineNum}: Invalid indentation jump` };
    }

    const trimmed = line.trim();

    // Check for multiline markers
    if (trimmed.endsWith('|') || trimmed.endsWith('>')) {
      inMultiline = true;
    } else if (indent <= prevIndent) {
      inMultiline = false;
    }

    // Check key-value format
    if (trimmed.includes(':') && !inMultiline) {
      const colonIdx = trimmed.indexOf(':');
      const afterColon = trimmed.slice(colonIdx + 1);

      // Value after colon should start with space or be empty
      if (afterColon && !afterColon.startsWith(' ') && !afterColon.startsWith('\n')) {
        // Check if it's a URL or timestamp
        if (!trimmed.includes('://') && !trimmed.match(/:\d{2}/)) {
          return { valid: false, error: `Line ${lineNum}: Missing space after colon` };
        }
      }
    }

    // Check for unquoted special characters that need quoting
    if (!inMultiline && trimmed.match(/^[^"']*:\s*[@*&!%]/)) {
      return { valid: false, error: `Line ${lineNum}: Special characters should be quoted` };
    }

    prevIndent = indent;
  }

  return { valid: true };
};

type Props = {
  data: YamlValidatorData | undefined;
  onChange: (next: YamlValidatorData) => void;
};

const YamlValidatorToolComponent = ({ data, onChange }: Props) => {
  const input = data?.input ?? '';
  const valid = data?.valid;
  const error = data?.error ?? '';

  const handleValidate = useCallback(() => {
    const result = validateYaml(input);
    onChange({ ...data, ...result });
  }, [input, data, onChange]);

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">YAML Validator</div>

      <textarea
        value={input}
        onChange={(e) => onChange({ ...data, input: e.target.value, valid: undefined, error: '' })}
        rows={10}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-emerald-500 font-mono"
        placeholder="name: my-app
version: 1.0.0
config:
  port: 3000
  debug: true"
      />

      <button
        type="button"
        onClick={handleValidate}
        className="w-full rounded bg-emerald-600 text-white text-xs py-2 hover:bg-emerald-500"
      >
        Validate YAML
      </button>

      {valid === true && (
        <div className="bg-emerald-900/30 border border-emerald-700 rounded p-2 text-[11px] text-emerald-300">
          ✓ Valid YAML syntax
        </div>
      )}

      {valid === false && error && (
        <div className="bg-red-900/30 border border-red-700 rounded p-2 text-[11px] text-red-300">
          ✗ {error}
        </div>
      )}

      <div className="text-[10px] text-slate-500">
        Validates basic YAML syntax including indentation, colons, and special characters.
      </div>
    </div>
  );
};

export class YamlValidatorTool {
  static Component = YamlValidatorToolComponent;
}
