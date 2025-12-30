import React, { useState } from 'react';
import type { CspBuilderData, CspDirectives } from './tool-types';

const COMMON_DIRECTIVES = [
  'default-src',
  'script-src',
  'style-src',
  'img-src',
  'font-src',
  'connect-src',
  'media-src',
  'object-src',
  'frame-src',
  'frame-ancestors',
  'base-uri',
  'form-action',
  'upgrade-insecure-requests'
];

const COMMON_VALUES = [
  "'self'",
  "'none'",
  "'unsafe-inline'",
  "'unsafe-eval'",
  'data:',
  'blob:',
  'https:',
  '*'
];

const analyzeCsp = (csp: string): string[] => {
  const warnings: string[] = [];
  const lowerCsp = csp.toLowerCase();

  // Check for unsafe-inline
  if (lowerCsp.includes("'unsafe-inline'")) {
    if (lowerCsp.includes('script-src') && lowerCsp.match(/script-src[^;]*'unsafe-inline'/)) {
      warnings.push("Warning: 'unsafe-inline' in script-src allows inline scripts, enabling XSS attacks");
    }
    if (lowerCsp.includes('style-src') && lowerCsp.match(/style-src[^;]*'unsafe-inline'/)) {
      warnings.push("Info: 'unsafe-inline' in style-src may be acceptable but reduces security");
    }
  }

  // Check for unsafe-eval
  if (lowerCsp.includes("'unsafe-eval'")) {
    warnings.push("Warning: 'unsafe-eval' allows eval() and similar functions, enabling code injection");
  }

  // Check for wildcard
  if (/ \*[ ;]/.test(csp) || / \*$/.test(csp)) {
    warnings.push("Warning: Wildcard (*) source allows loading from any origin");
  }

  // Check for https: scheme
  if (/https:[ ;]/.test(csp) || /https:$/.test(csp)) {
    warnings.push("Warning: 'https:' allows any HTTPS origin, consider using specific domains");
  }

  // Check for missing default-src
  if (!lowerCsp.includes('default-src')) {
    warnings.push("Warning: Missing 'default-src' - this is the fallback for undefined directives");
  }

  // Check for data: in script-src
  if (lowerCsp.match(/script-src[^;]*data:/)) {
    warnings.push("Critical: 'data:' in script-src allows data URI scripts, high XSS risk");
  }

  // Check for missing object-src
  if (!lowerCsp.includes('object-src')) {
    warnings.push("Info: Consider adding 'object-src' to block plugins");
  }

  // Check for missing base-uri
  if (!lowerCsp.includes('base-uri')) {
    warnings.push("Info: Consider adding 'base-uri' to prevent base tag injection");
  }

  // Check for missing frame-ancestors
  if (!lowerCsp.includes('frame-ancestors')) {
    warnings.push("Info: Consider adding 'frame-ancestors' to prevent clickjacking");
  }

  return warnings;
};

const generateCsp = (directives: CspDirectives, reportOnly: boolean): string => {
  const parts: string[] = [];

  for (const [directive, values] of Object.entries(directives)) {
    if (values && values.length > 0) {
      parts.push(`${directive} ${values.join(' ')}`);
    }
  }

  if (parts.length === 0) {
    return '';
  }

  const header = reportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
  return `${header}: ${parts.join('; ')}`;
};

type Props = {
  data: CspBuilderData | undefined;
  onChange: (next: CspBuilderData) => void;
};

const CspBuilderToolComponent = ({ data, onChange }: Props) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const directives = data?.directives ?? {};
  const warnings = data?.warnings ?? [];
  const reportOnly = data?.reportOnly ?? false;
  const error = data?.error;
  const [copied, setCopied] = useState(false);
  const [activeDirective, setActiveDirective] = useState<string>('default-src');
  const [customValue, setCustomValue] = useState('');

  const handleGenerate = () => {
    if (Object.keys(directives).length === 0) {
      onChange({ ...data, error: 'Add at least one directive' });
      return;
    }
    const cspOutput = generateCsp(directives, reportOnly);
    onChange({ ...data, output: cspOutput, error: undefined });
  };

  const handleAnalyze = () => {
    if (!input.trim()) {
      onChange({ ...data, error: 'Enter a CSP header to analyze' });
      return;
    }
    const analysisWarnings = analyzeCsp(input);
    onChange({ ...data, warnings: analysisWarnings, analyzed: true, error: undefined });
  };

  const handleAddValue = (directive: string, value: string) => {
    const currentValues = directives[directive] || [];
    if (!currentValues.includes(value)) {
      onChange({
        ...data,
        directives: {
          ...directives,
          [directive]: [...currentValues, value]
        }
      });
    }
  };

  const handleRemoveValue = (directive: string, value: string) => {
    const currentValues = directives[directive] || [];
    const newValues = currentValues.filter(v => v !== value);
    if (newValues.length === 0) {
      const { [directive]: _, ...rest } = directives;
      onChange({ ...data, directives: rest });
    } else {
      onChange({
        ...data,
        directives: {
          ...directives,
          [directive]: newValues
        }
      });
    }
  };

  const handleAddCustomValue = () => {
    if (customValue.trim()) {
      handleAddValue(activeDirective, customValue.trim());
      setCustomValue('');
    }
  };

  const handleCopy = () => {
    if (output) {
      navigator.clipboard.writeText(output);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  };

  const applyStrictPreset = () => {
    onChange({
      ...data,
      directives: {
        'default-src': ["'none'"],
        'script-src': ["'self'"],
        'style-src': ["'self'"],
        'img-src': ["'self'"],
        'font-src': ["'self'"],
        'connect-src': ["'self'"],
        'frame-ancestors': ["'none'"],
        'base-uri': ["'self'"],
        'form-action': ["'self'"],
        'object-src': ["'none'"]
      }
    });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">CSP Builder & Analyzer</div>

      {/* Mode tabs */}
      <div className="flex gap-2">
        <button
          type="button"
          onClick={applyStrictPreset}
          className="flex-1 rounded bg-slate-700 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-600 transition-colors"
        >
          Strict Preset
        </button>
        <label className="flex items-center gap-1 text-[10px] text-slate-400">
          <input
            type="checkbox"
            checked={reportOnly}
            onChange={(e) => onChange({ ...data, reportOnly: e.target.checked })}
            className="rounded border-slate-600 bg-slate-800 text-emerald-500"
          />
          Report Only
        </label>
      </div>

      {/* Directive selector */}
      <div className="space-y-1">
        <div className="text-[11px] text-slate-400">Directive</div>
        <select
          value={activeDirective}
          onChange={(e) => setActiveDirective(e.target.value)}
          className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1.5 border border-slate-700 focus:outline-none focus:border-emerald-500"
        >
          {COMMON_DIRECTIVES.map((d) => (
            <option key={d} value={d}>{d}</option>
          ))}
        </select>
      </div>

      {/* Value buttons */}
      <div className="space-y-1">
        <div className="text-[11px] text-slate-400">Add Value</div>
        <div className="flex flex-wrap gap-1">
          {COMMON_VALUES.map((val) => (
            <button
              key={val}
              type="button"
              onClick={() => handleAddValue(activeDirective, val)}
              className="rounded bg-slate-700 px-2 py-0.5 text-[10px] text-slate-300 hover:bg-slate-600 transition-colors"
            >
              {val}
            </button>
          ))}
        </div>
        <div className="flex gap-1">
          <input
            type="text"
            value={customValue}
            onChange={(e) => setCustomValue(e.target.value)}
            placeholder="Custom value (e.g., https://cdn.example.com)"
            className="flex-1 rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-emerald-500"
            onKeyDown={(e) => e.key === 'Enter' && handleAddCustomValue()}
          />
          <button
            type="button"
            onClick={handleAddCustomValue}
            className="rounded bg-slate-600 px-2 py-1 text-[10px] text-white hover:bg-slate-500 transition-colors"
          >
            Add
          </button>
        </div>
      </div>

      {/* Current directives display */}
      {Object.keys(directives).length > 0 && (
        <div className="space-y-1">
          <div className="text-[11px] text-slate-400">Current Directives</div>
          <div className="bg-slate-800 rounded p-2 space-y-1 max-h-32 overflow-y-auto">
            {Object.entries(directives).map(([dir, vals]) => (
              <div key={dir} className="text-[10px]">
                <span className="text-emerald-400">{dir}:</span>
                <div className="flex flex-wrap gap-1 mt-0.5">
                  {vals.map((val) => (
                    <span
                      key={val}
                      className="inline-flex items-center gap-1 bg-slate-700 rounded px-1.5 py-0.5 text-slate-300"
                    >
                      {val}
                      <button
                        type="button"
                        onClick={() => handleRemoveValue(dir, val)}
                        className="text-rose-400 hover:text-rose-300"
                      >
                        ×
                      </button>
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Generate button */}
      <button
        type="button"
        onClick={handleGenerate}
        className="w-full rounded bg-emerald-600 px-2 py-1.5 text-xs text-white hover:bg-emerald-500 transition-colors"
      >
        Generate
      </button>

      {/* Generated output */}
      {output && (
        <div className="space-y-1">
          <div className="flex items-center justify-between">
            <div className="text-[11px] text-slate-400">Generated CSP Header</div>
            <button
              type="button"
              onClick={handleCopy}
              className="text-[10px] text-slate-400 hover:text-white transition-colors"
            >
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <div className="bg-slate-900 border border-slate-700 rounded p-2 text-[10px] text-slate-200 font-mono break-all select-all">
            {output}
          </div>
        </div>
      )}

      {/* Analyzer section */}
      <div className="border-t border-slate-700 pt-3 space-y-2">
        <div className="text-[11px] text-slate-400">Analyze Existing CSP</div>
        <textarea
          value={input}
          onChange={(e) => onChange({ ...data, input: e.target.value })}
          rows={2}
          className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-emerald-500 font-mono"
          placeholder="Paste CSP header to analyze..."
        />
        <button
          type="button"
          onClick={handleAnalyze}
          className="w-full rounded bg-slate-600 px-2 py-1.5 text-xs text-white hover:bg-slate-500 transition-colors"
        >
          Analyze
        </button>
      </div>

      {/* Analysis warnings */}
      {warnings.length > 0 && (
        <div className="space-y-1">
          <div className="text-[11px] text-slate-400">Analysis Results</div>
          <div className="space-y-1">
            {warnings.map((warning, i) => (
              <div
                key={i}
                className={`text-[10px] rounded px-2 py-1 ${
                  warning.startsWith('Critical')
                    ? 'bg-red-900/30 text-red-300 border border-red-800'
                    : warning.startsWith('Warning')
                    ? 'bg-yellow-900/30 text-yellow-300 border border-yellow-800'
                    : 'bg-blue-900/30 text-blue-300 border border-blue-800'
                }`}
              >
                {warning}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Error display */}
      {error && (
        <div className="text-[11px] text-rose-300 bg-rose-900/20 border border-rose-800 rounded px-2 py-1.5">
          {error}
        </div>
      )}

      {/* Info */}
      <div className="text-[10px] text-slate-500">
        Build and analyze Content-Security-Policy headers to protect against XSS and injection attacks.
      </div>
    </div>
  );
};

export class CspBuilderTool {
  static Component = CspBuilderToolComponent;
}
