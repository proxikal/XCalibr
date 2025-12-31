import React from 'react';

export type SqlSchemaGeneratorData = {
  input?: string;
  output?: string;
  tableName?: string;
  dialect?: 'mysql' | 'postgresql' | 'sqlite';
  includePrimaryKey?: boolean;
  error?: string;
};

type Props = {
  data: SqlSchemaGeneratorData | undefined;
  onChange: (data: SqlSchemaGeneratorData) => void;
};

const toSqlType = (value: unknown, dialect: string): string => {
  if (value === null) return 'TEXT';

  switch (typeof value) {
    case 'string':
      if (value.length > 255) return 'TEXT';
      return dialect === 'postgresql' ? 'VARCHAR(255)' : 'VARCHAR(255)';
    case 'number':
      if (Number.isInteger(value)) {
        if (value > 2147483647) return 'BIGINT';
        return 'INT';
      }
      return dialect === 'postgresql' ? 'DOUBLE PRECISION' : 'DOUBLE';
    case 'boolean':
      return dialect === 'postgresql' ? 'BOOLEAN' : 'TINYINT(1)';
    case 'object':
      if (Array.isArray(value)) return 'JSON';
      return 'JSON';
    default:
      return 'TEXT';
  }
};

const generateSchema = (
  obj: Record<string, unknown>,
  tableName: string,
  dialect: string,
  includePrimaryKey: boolean
): string => {
  const lines: string[] = [];
  const columns: string[] = [];

  if (includePrimaryKey) {
    if (dialect === 'postgresql') {
      columns.push('  id SERIAL PRIMARY KEY');
    } else if (dialect === 'sqlite') {
      columns.push('  id INTEGER PRIMARY KEY AUTOINCREMENT');
    } else {
      columns.push('  id INT AUTO_INCREMENT PRIMARY KEY');
    }
  }

  for (const [key, value] of Object.entries(obj)) {
    const columnName = key.toLowerCase().replace(/[^a-z0-9_]/g, '_');
    const sqlType = toSqlType(value, dialect);
    columns.push(`  ${columnName} ${sqlType}`);
  }

  lines.push(`CREATE TABLE ${tableName} (`);
  lines.push(columns.join(',\n'));
  lines.push(');');

  return lines.join('\n');
};

const SqlSchemaGenerator: React.FC<Props> = ({ data, onChange }) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const tableName = data?.tableName ?? 'my_table';
  const dialect = data?.dialect ?? 'mysql';
  const includePrimaryKey = data?.includePrimaryKey ?? true;
  const error = data?.error ?? '';

  const handleGenerate = () => {
    try {
      const parsed = JSON.parse(input);
      if (typeof parsed !== 'object' || parsed === null) {
        throw new Error('Input must be a JSON object');
      }
      const obj = Array.isArray(parsed) ? (parsed[0] ?? {}) : parsed;
      const generated = generateSchema(obj as Record<string, unknown>, tableName, dialect, includePrimaryKey);
      onChange({ ...data, output: generated, error: '' });
    } catch (e) {
      onChange({
        ...data,
        error: e instanceof Error ? e.message : 'Invalid JSON'
      });
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(output);
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Table Name</label>
          <input
            type="text"
            value={tableName}
            onChange={(e) => onChange({ ...data, tableName: e.target.value })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">SQL Dialect</label>
          <select
            value={dialect}
            onChange={(e) => onChange({ ...data, dialect: e.target.value as 'mysql' | 'postgresql' | 'sqlite' })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          >
            <option value="mysql">MySQL</option>
            <option value="postgresql">PostgreSQL</option>
            <option value="sqlite">SQLite</option>
          </select>
        </div>
      </div>

      <label className="flex items-center gap-2 text-sm text-gray-300">
        <input
          type="checkbox"
          checked={includePrimaryKey}
          onChange={(e) => onChange({ ...data, includePrimaryKey: e.target.checked })}
          className="rounded bg-gray-700 border-gray-600"
        />
        Include auto-increment primary key (id)
      </label>

      <div>
        <label className="block text-xs text-gray-400 mb-1">JSON Input</label>
        <textarea
          value={input}
          onChange={(e) => onChange({ ...data, input: e.target.value })}
          placeholder='{"name": "John", "age": 30, "email": "john@example.com"}'
          className="w-full h-28 px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-xs resize-none"
        />
      </div>

      <button
        onClick={handleGenerate}
        disabled={!input.trim()}
        className="w-full py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white rounded text-sm"
      >
        Generate SQL Schema
      </button>

      {error && (
        <div className="text-red-400 text-xs p-2 bg-red-900/20 rounded">
          {error}
        </div>
      )}

      {output && !error && (
        <div className="space-y-2">
          <div className="flex justify-between items-center">
            <span className="text-xs text-gray-400">SQL CREATE TABLE</span>
            <button onClick={handleCopy} className="text-xs text-blue-400 hover:text-blue-300">
              Copy
            </button>
          </div>
          <textarea
            readOnly
            value={output}
            className="w-full h-32 px-3 py-2 bg-[#0d0d1a] border border-gray-700 rounded text-green-400 font-mono text-xs resize-none"
          />
        </div>
      )}

      <div className="text-xs text-gray-500">
        Infers SQL types from JSON values. Arrays and objects become JSON type.
      </div>
    </div>
  );
};

export class SqlSchemaGeneratorTool {
  static Component = SqlSchemaGenerator;
}
