import React from 'react';

export type ObjectIdGeneratorData = {
  objectId?: string;
  objectIds?: string[];
  count?: number;
  timestamp?: string;
  showParts?: boolean;
};

type Props = {
  data: ObjectIdGeneratorData | undefined;
  onChange: (data: ObjectIdGeneratorData) => void;
};

const generateObjectId = (): string => {
  const timestamp = Math.floor(Date.now() / 1000).toString(16).padStart(8, '0');
  const machineId = Array.from({ length: 3 }, () =>
    Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
  ).join('');
  const processId = Math.floor(Math.random() * 65536).toString(16).padStart(4, '0');
  const counter = Math.floor(Math.random() * 16777216).toString(16).padStart(6, '0');

  return timestamp + machineId + processId + counter;
};

const parseObjectId = (id: string) => {
  if (id.length !== 24) return null;

  const timestampHex = id.slice(0, 8);
  const machineId = id.slice(8, 14);
  const processId = id.slice(14, 18);
  const counter = id.slice(18, 24);

  const timestampSeconds = parseInt(timestampHex, 16);
  const date = new Date(timestampSeconds * 1000);

  return {
    timestamp: date.toLocaleString(),
    timestampHex,
    machineId,
    processId,
    counter
  };
};

const ObjectIdGenerator: React.FC<Props> = ({ data, onChange }) => {
  const objectId = data?.objectId ?? '';
  const objectIds = data?.objectIds ?? [];
  const count = data?.count ?? 1;
  const showParts = data?.showParts ?? true;

  const handleGenerate = () => {
    const generated: string[] = [];

    for (let i = 0; i < count; i++) {
      generated.push(generateObjectId());
    }

    const parsed = parseObjectId(generated[0]);

    onChange({
      ...data,
      objectId: generated[0],
      objectIds: count > 1 ? generated : [],
      timestamp: parsed?.timestamp
    });
  };

  const handleCopy = (value: string) => {
    navigator.clipboard.writeText(value);
  };

  const handleCopyAll = () => {
    const allIds = objectIds.length > 0 ? objectIds.join('\n') : objectId;
    navigator.clipboard.writeText(allIds);
  };

  const parsed = objectId ? parseObjectId(objectId) : null;

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs text-gray-400 mb-1">Count (Bulk)</label>
        <input
          type="number"
          min={1}
          max={100}
          value={count}
          onChange={(e) => onChange({ ...data, count: Math.min(100, Math.max(1, parseInt(e.target.value) || 1)) })}
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-sm"
        />
      </div>

      <label className="flex items-center gap-2 text-sm text-gray-300">
        <input
          type="checkbox"
          checked={showParts}
          onChange={(e) => onChange({ ...data, showParts: e.target.checked })}
          className="rounded bg-gray-700 border-gray-600"
        />
        Show ObjectId parts breakdown
      </label>

      <button
        onClick={handleGenerate}
        className="w-full py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-sm"
      >
        Generate ObjectId{count > 1 ? 's' : ''}
      </button>

      {objectId && (
        <div className="space-y-2">
          <div
            onClick={() => handleCopy(objectId)}
            className="bg-[#0d0d1a] border border-gray-700 rounded p-3 cursor-pointer hover:border-blue-500"
            title="Click to copy"
          >
            <div className="text-xs text-gray-400 mb-1">Generated ObjectId (MongoDB)</div>
            <div className="font-mono text-green-400 text-sm break-all">{objectId}</div>
          </div>

          {showParts && parsed && (
            <div className="bg-[#1a1a2e] border border-gray-700 rounded p-3 space-y-2">
              <div className="text-xs text-gray-400">ObjectId Breakdown</div>
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div>
                  <span className="text-gray-500">Timestamp:</span>
                  <span className="ml-2 text-blue-400 font-mono">{parsed.timestampHex}</span>
                </div>
                <div>
                  <span className="text-gray-500">Date:</span>
                  <span className="ml-2 text-green-400">{parsed.timestamp}</span>
                </div>
                <div>
                  <span className="text-gray-500">Machine ID:</span>
                  <span className="ml-2 text-yellow-400 font-mono">{parsed.machineId}</span>
                </div>
                <div>
                  <span className="text-gray-500">Process ID:</span>
                  <span className="ml-2 text-purple-400 font-mono">{parsed.processId}</span>
                </div>
                <div>
                  <span className="text-gray-500">Counter:</span>
                  <span className="ml-2 text-pink-400 font-mono">{parsed.counter}</span>
                </div>
              </div>
            </div>
          )}

          {objectIds.length > 1 && (
            <>
              <div className="flex justify-between items-center">
                <span className="text-xs text-gray-400">Bulk ObjectIds ({objectIds.length})</span>
                <button
                  onClick={handleCopyAll}
                  className="text-xs text-blue-400 hover:text-blue-300"
                >
                  Copy All
                </button>
              </div>
              <div className="max-h-48 overflow-y-auto space-y-1">
                {objectIds.map((id, idx) => (
                  <div
                    key={idx}
                    onClick={() => handleCopy(id)}
                    className="bg-[#1a1a2e] p-2 rounded text-xs font-mono text-gray-300 cursor-pointer hover:bg-gray-800"
                    title="Click to copy"
                  >
                    {id}
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      )}

      <div className="text-xs text-gray-500">
        ObjectIds are 24-character hex strings used as MongoDB document identifiers.
      </div>
    </div>
  );
};

export class ObjectIdGeneratorTool {
  static Component = ObjectIdGenerator;
}
