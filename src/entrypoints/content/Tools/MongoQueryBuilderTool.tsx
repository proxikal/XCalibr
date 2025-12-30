import React from 'react';
import type {
  MongoQueryBuilderData
} from './tool-types';

const MongoQueryBuilderToolComponent = ({
  data,
  onChange
}: {
  data: MongoQueryBuilderData | undefined;
  onChange: (next: MongoQueryBuilderData) => void;
}) => {
  const collection = data?.collection ?? '';
  const filter = data?.filter ?? '{}';
  const projection = data?.projection ?? '{}';
  const sort = data?.sort ?? '{}';
  const limit = data?.limit ?? '';
  const output = data?.output ?? '';
  const error = data?.error ?? '';

  const handleBuild = () => {
    try {
      JSON.parse(filter);
      JSON.parse(projection);
      JSON.parse(sort);
      const limitValue = limit.trim() ? `.limit(${limit.trim()})` : '';
      const query = `db.${collection || 'collection'}.find(${filter}, ${projection}).sort(${sort})${limitValue}`;
      onChange({ collection, filter, projection, sort, limit, output: query, error: '' });
    } catch (err) {
      onChange({
        collection,
        filter,
        projection,
        sort,
        limit,
        output: '',
        error: err instanceof Error ? err.message : 'Invalid JSON'
      });
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Mongo Query Builder</div>
      <input
        type="text"
        value={collection}
        onChange={(event) =>
          onChange({ collection: event.target.value, filter, projection, sort, limit, output, error })
        }
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="Collection name"
      />
      <textarea
        value={filter}
        onChange={(event) =>
          onChange({ collection, filter: event.target.value, projection, sort, limit, output, error })
        }
        rows={3}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder='Filter (e.g. {"status":"active"})'
      />
      <textarea
        value={projection}
        onChange={(event) =>
          onChange({ collection, filter, projection: event.target.value, sort, limit, output, error })
        }
        rows={3}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder='Projection (e.g. {"name":1})'
      />
      <textarea
        value={sort}
        onChange={(event) =>
          onChange({ collection, filter, projection, sort: event.target.value, limit, output, error })
        }
        rows={3}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder='Sort (e.g. {"createdAt":-1})'
      />
      <input
        type="text"
        value={limit}
        onChange={(event) =>
          onChange({ collection, filter, projection, sort, limit: event.target.value, output, error })
        }
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="Limit"
      />
      {error ? (
        <div className="text-[11px] text-rose-300">{error}</div>
      ) : null}
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
        rows={3}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Mongo query output..."
      />
    </div>
  );
};
export class MongoQueryBuilderTool {
  static Component = MongoQueryBuilderToolComponent;
}
