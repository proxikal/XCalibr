import React from 'react';

export type UuidGeneratorData = {
  uuid?: string;
  uuids?: string[];
  version?: 'v4' | 'v1';
  count?: number;
  uppercase?: boolean;
};

type Props = {
  data: UuidGeneratorData | undefined;
  onChange: (data: UuidGeneratorData) => void;
};

const generateUuidV4 = (): string => {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
};

const generateUuidV1 = (): string => {
  const now = Date.now();
  const timeHex = now.toString(16).padStart(12, '0');
  const timeLow = timeHex.slice(-8);
  const timeMid = timeHex.slice(-12, -8);
  const timeHiVersion = '1' + timeHex.slice(0, 3);
  const clockSeq = ((Math.random() * 0x3fff) | 0x8000).toString(16);
  const node = Array.from({ length: 6 }, () =>
    Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
  ).join('');

  return `${timeLow}-${timeMid}-${timeHiVersion}-${clockSeq}-${node}`;
};

const UuidGenerator: React.FC<Props> = ({ data, onChange }) => {
  const uuid = data?.uuid ?? '';
  const uuids = data?.uuids ?? [];
  const version = data?.version ?? 'v4';
  const count = data?.count ?? 1;
  const uppercase = data?.uppercase ?? false;

  const handleGenerate = () => {
    const generator = version === 'v4' ? generateUuidV4 : generateUuidV1;
    const generated: string[] = [];

    for (let i = 0; i < count; i++) {
      let id = generator();
      if (uppercase) id = id.toUpperCase();
      generated.push(id);
    }

    onChange({
      ...data,
      uuid: generated[0],
      uuids: count > 1 ? generated : []
    });
  };

  const handleCopy = (value: string) => {
    navigator.clipboard.writeText(value);
  };

  const handleCopyAll = () => {
    const allUuids = uuids.length > 0 ? uuids.join('\n') : uuid;
    navigator.clipboard.writeText(allUuids);
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Version</label>
          <select
            value={version}
            onChange={(e) => onChange({ ...data, version: e.target.value as 'v4' | 'v1' })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          >
            <option value="v4">UUID v4 (Random)</option>
            <option value="v1">UUID v1 (Timestamp)</option>
          </select>
        </div>
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
      </div>

      <label className="flex items-center gap-2 text-sm text-gray-300">
        <input
          type="checkbox"
          checked={uppercase}
          onChange={(e) => onChange({ ...data, uppercase: e.target.checked })}
          className="rounded bg-gray-700 border-gray-600"
        />
        Uppercase
      </label>

      <button
        onClick={handleGenerate}
        className="w-full py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-sm"
      >
        Generate UUID{count > 1 ? 's' : ''}
      </button>

      {uuid && (
        <div className="space-y-2">
          <div
            onClick={() => handleCopy(uuid)}
            className="bg-[#0d0d1a] border border-gray-700 rounded p-3 cursor-pointer hover:border-blue-500"
            title="Click to copy"
          >
            <div className="text-xs text-gray-400 mb-1">Generated UUID</div>
            <div className="font-mono text-green-400 text-sm break-all">{uuid}</div>
          </div>

          {uuids.length > 1 && (
            <>
              <div className="flex justify-between items-center">
                <span className="text-xs text-gray-400">Bulk UUIDs ({uuids.length})</span>
                <button
                  onClick={handleCopyAll}
                  className="text-xs text-blue-400 hover:text-blue-300"
                >
                  Copy All
                </button>
              </div>
              <div className="max-h-48 overflow-y-auto space-y-1">
                {uuids.map((id, idx) => (
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
        {version === 'v4' ? 'Random UUIDs are generated using crypto-quality randomness.' : 'Timestamp-based UUIDs include current time.'}
      </div>
    </div>
  );
};

export class UuidGeneratorTool {
  static Component = UuidGenerator;
}
