import React from 'react';
import {
  fromDynamo,
  toDynamo
} from './helpers';
import type {
  DynamoDbConverterData
} from './tool-types';

const DynamoDbConverterToolComponent = ({
  data,
  onChange
}: {
  data: DynamoDbConverterData | undefined;
  onChange: (next: DynamoDbConverterData) => void;
}) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const mode = data?.mode ?? 'toDynamo';
  const error = data?.error ?? '';

  const handleConvert = () => {
    try {
      const parsed = JSON.parse(input);
      const result = mode === 'toDynamo' ? toDynamo(parsed) : fromDynamo(parsed);
      onChange({ input, output: JSON.stringify(result, null, 2), mode, error: '' });
    } catch (err) {
      onChange({
        input,
        output: '',
        mode,
        error: err instanceof Error ? err.message : 'Invalid JSON'
      });
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">DynamoDB JSON Converter</div>
      <div className="flex gap-2">
        {(['toDynamo', 'fromDynamo'] as const).map((option) => (
          <button
            key={option}
            type="button"
            onClick={() => onChange({ input, output, mode: option, error })}
            className={`flex-1 rounded px-2 py-1 text-[11px] border transition-colors ${
              mode === option
                ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
            }`}
          >
            {option === 'toDynamo' ? 'To Dynamo' : 'From Dynamo'}
          </button>
        ))}
      </div>
      <textarea
        value={input}
        onChange={(event) => onChange({ input: event.target.value, output, mode, error })}
        rows={5}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Paste JSON..."
      />
      {error ? (
        <div className="text-[11px] text-rose-300">{error}</div>
      ) : null}
      <button
        type="button"
        onClick={handleConvert}
        disabled={!input.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Convert
      </button>
      <textarea
        value={output}
        readOnly
        rows={5}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Converted output..."
      />
    </div>
  );
};
export class DynamoDbConverterTool {
  static Component = DynamoDbConverterToolComponent;
}
