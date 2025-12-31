import React, { useEffect, useState } from 'react';

export type UnixTimestampData = {
  timestamp?: number;
  humanDate?: string;
  inputTimestamp?: string;
  inputDate?: string;
  format?: 'seconds' | 'milliseconds';
};

type Props = {
  data: UnixTimestampData | undefined;
  onChange: (data: UnixTimestampData) => void;
};

const UnixTimestamp: React.FC<Props> = ({ data, onChange }) => {
  const inputTimestamp = data?.inputTimestamp ?? '';
  const inputDate = data?.inputDate ?? '';
  const humanDate = data?.humanDate ?? '';
  const timestamp = data?.timestamp;
  const format = data?.format ?? 'seconds';

  const [currentTime, setCurrentTime] = useState(Math.floor(Date.now() / 1000));

  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentTime(Math.floor(Date.now() / 1000));
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleTimestampConvert = () => {
    const ts = parseInt(inputTimestamp);
    if (isNaN(ts)) return;

    const ms = format === 'seconds' ? ts * 1000 : ts;
    const date = new Date(ms);

    onChange({
      ...data,
      timestamp: ts,
      humanDate: date.toISOString()
    });
  };

  const handleDateConvert = () => {
    const date = new Date(inputDate);
    if (isNaN(date.getTime())) return;

    const ts = format === 'seconds'
      ? Math.floor(date.getTime() / 1000)
      : date.getTime();

    onChange({
      ...data,
      timestamp: ts,
      humanDate: date.toISOString()
    });
  };

  const copyTimestamp = (ts: number) => {
    navigator.clipboard.writeText(ts.toString());
  };

  return (
    <div className="space-y-4">
      <div className="bg-[#1a1a2e] border border-gray-700 rounded p-4 text-center">
        <div className="text-xs text-gray-400 mb-1">Current Unix Timestamp</div>
        <div
          className="text-2xl font-mono text-green-400 cursor-pointer hover:text-green-300"
          onClick={() => copyTimestamp(currentTime)}
          title="Click to copy"
        >
          {currentTime}
        </div>
        <div className="text-xs text-gray-500 mt-1">
          {new Date(currentTime * 1000).toISOString()}
        </div>
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Format</label>
        <select
          value={format}
          onChange={(e) => onChange({ ...data, format: e.target.value as typeof format })}
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
        >
          <option value="seconds">Seconds</option>
          <option value="milliseconds">Milliseconds</option>
        </select>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <label className="block text-xs text-gray-400">Timestamp to Date</label>
          <input
            type="text"
            value={inputTimestamp}
            onChange={(e) => onChange({ ...data, inputTimestamp: e.target.value })}
            placeholder="Enter timestamp..."
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-sm"
          />
          <button
            onClick={handleTimestampConvert}
            disabled={!inputTimestamp}
            className="w-full py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white rounded text-sm"
          >
            Convert
          </button>
        </div>

        <div className="space-y-2">
          <label className="block text-xs text-gray-400">Date to Timestamp</label>
          <input
            type="datetime-local"
            value={inputDate}
            onChange={(e) => onChange({ ...data, inputDate: e.target.value })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          />
          <button
            onClick={handleDateConvert}
            disabled={!inputDate}
            className="w-full py-2 bg-green-600 hover:bg-green-500 disabled:bg-gray-600 text-white rounded text-sm"
          >
            Convert
          </button>
        </div>
      </div>

      {humanDate && timestamp !== undefined && (
        <div className="bg-[#0d0d1a] border border-gray-700 rounded p-3">
          <div className="text-xs text-gray-400 mb-2">Result</div>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <div className="text-gray-400 text-xs">Timestamp</div>
              <div className="text-green-400 font-mono">{timestamp}</div>
            </div>
            <div>
              <div className="text-gray-400 text-xs">ISO Date</div>
              <div className="text-blue-400 font-mono text-xs">{humanDate}</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export class UnixTimestampTool {
  static Component = UnixTimestamp;
}
