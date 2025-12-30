import React from 'react';
import {
  buildSqlQuery
} from './helpers';
import type {
  SqlQueryBuilderData
} from './tool-types';

const SqlQueryBuilderToolComponent = ({
  data,
  onChange
}: {
  data: SqlQueryBuilderData | undefined;
  onChange: (next: SqlQueryBuilderData) => void;
}) => {
  const table = data?.table ?? '';
  const columns = data?.columns ?? '';
  const where = data?.where ?? '';
  const orderBy = data?.orderBy ?? '';
  const limit = data?.limit ?? '';
  const output = data?.output ?? '';

  const handleBuild = () => {
    const query = buildSqlQuery({
      table,
      columns: columns
        .split(',')
        .map((entry) => entry.trim())
        .filter(Boolean),
      where,
      orderBy,
      limit
    });
    onChange({ table, columns, where, orderBy, limit, output: query });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">SQL Query Builder</div>
      <input
        type="text"
        value={table}
        onChange={(event) =>
          onChange({ table: event.target.value, columns, where, orderBy, limit, output })
        }
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="Table name"
      />
      <input
        type="text"
        value={columns}
        onChange={(event) =>
          onChange({ table, columns: event.target.value, where, orderBy, limit, output })
        }
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="Columns (comma separated)"
      />
      <input
        type="text"
        value={where}
        onChange={(event) =>
          onChange({ table, columns, where: event.target.value, orderBy, limit, output })
        }
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="WHERE clause"
      />
      <input
        type="text"
        value={orderBy}
        onChange={(event) =>
          onChange({ table, columns, where, orderBy: event.target.value, limit, output })
        }
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="ORDER BY clause"
      />
      <input
        type="text"
        value={limit}
        onChange={(event) =>
          onChange({ table, columns, where, orderBy, limit: event.target.value, output })
        }
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="LIMIT"
      />
      <button
        type="button"
        onClick={handleBuild}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
      >
        Build Query
      </button>
      <textarea
        value={output}
        readOnly
        rows={4}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="SQL output..."
      />
    </div>
  );
};
export class SqlQueryBuilderTool {
  static Component = SqlQueryBuilderToolComponent;
}
