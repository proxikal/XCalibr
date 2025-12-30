import React from 'react';
import {
  validateJsonSchema
} from './helpers';
import type {
  JsonSchemaValidatorData
} from './tool-types';

const JsonSchemaValidatorToolComponent = ({
  data,
  onChange
}: {
  data: JsonSchemaValidatorData | undefined;
  onChange: (next: JsonSchemaValidatorData) => void;
}) => {
  const schema = data?.schema ?? '';
  const input = data?.input ?? '';
  const issues = data?.issues ?? [];
  const error = data?.error ?? '';

  const handleValidate = () => {
    try {
      const parsedSchema = JSON.parse(schema);
      const parsedInput = JSON.parse(input);
      const result = validateJsonSchema(parsedSchema, parsedInput);
      onChange({
        schema,
        input,
        issues: result.map((issue) => `${issue.path}: ${issue.message}`),
        error: ''
      });
    } catch (err) {
      onChange({
        schema,
        input,
        issues: [],
        error: err instanceof Error ? err.message : 'Invalid JSON'
      });
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">JSON Schema Validator</div>
      <textarea
        value={schema}
        onChange={(event) =>
          onChange({ schema: event.target.value, input, issues, error })
        }
        rows={5}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Paste JSON schema..."
      />
      <textarea
        value={input}
        onChange={(event) =>
          onChange({ schema, input: event.target.value, issues, error })
        }
        rows={5}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Paste JSON data..."
      />
      {error ? (
        <div className="text-[11px] text-rose-300">{error}</div>
      ) : null}
      <button
        type="button"
        onClick={handleValidate}
        disabled={!schema.trim() || !input.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Validate
      </button>
      <div className="rounded border border-slate-800 bg-slate-900/60 p-3 text-[11px] text-slate-300 max-h-32 overflow-y-auto no-scrollbar">
        {issues.length === 0 ? 'No validation issues found.' : issues.join('\n')}
      </div>
    </div>
  );
};
export class JsonSchemaValidatorTool {
  static Component = JsonSchemaValidatorToolComponent;
}
