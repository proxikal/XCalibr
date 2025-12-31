import React from 'react';

export type TimezoneConverterData = {
  inputTime?: string;
  sourceTimezone?: string;
  conversions?: { timezone: string; time: string; offset: string }[];
};

type Props = {
  data: TimezoneConverterData | undefined;
  onChange: (data: TimezoneConverterData) => void;
};

const timezones = [
  { id: 'UTC', label: 'UTC', offset: 0 },
  { id: 'America/New_York', label: 'New York (EST/EDT)', offset: -5 },
  { id: 'America/Los_Angeles', label: 'Los Angeles (PST/PDT)', offset: -8 },
  { id: 'America/Chicago', label: 'Chicago (CST/CDT)', offset: -6 },
  { id: 'Europe/London', label: 'London (GMT/BST)', offset: 0 },
  { id: 'Europe/Paris', label: 'Paris (CET/CEST)', offset: 1 },
  { id: 'Europe/Berlin', label: 'Berlin (CET/CEST)', offset: 1 },
  { id: 'Asia/Tokyo', label: 'Tokyo (JST)', offset: 9 },
  { id: 'Asia/Shanghai', label: 'Shanghai (CST)', offset: 8 },
  { id: 'Asia/Dubai', label: 'Dubai (GST)', offset: 4 },
  { id: 'Asia/Singapore', label: 'Singapore (SGT)', offset: 8 },
  { id: 'Australia/Sydney', label: 'Sydney (AEST/AEDT)', offset: 10 },
  { id: 'Asia/Kolkata', label: 'Mumbai (IST)', offset: 5.5 }
];

const TimezoneConverter: React.FC<Props> = ({ data, onChange }) => {
  const inputTime = data?.inputTime ?? '';
  const sourceTimezone = data?.sourceTimezone ?? 'UTC';
  const conversions = data?.conversions ?? [];

  const handleConvert = () => {
    if (!inputTime) return;

    const [hours, minutes] = inputTime.split(':').map(Number);
    const sourceOffset = timezones.find(tz => tz.id === sourceTimezone)?.offset ?? 0;

    const results = timezones.map(tz => {
      const diff = tz.offset - sourceOffset;
      let newHours = hours + diff;
      let dayOffset = '';

      if (newHours >= 24) {
        newHours -= 24;
        dayOffset = ' (+1 day)';
      } else if (newHours < 0) {
        newHours += 24;
        dayOffset = ' (-1 day)';
      }

      const formatted = `${String(Math.floor(newHours)).padStart(2, '0')}:${String(minutes).padStart(2, '0')}${dayOffset}`;

      return {
        timezone: tz.label,
        time: formatted,
        offset: `UTC${tz.offset >= 0 ? '+' : ''}${tz.offset}`
      };
    });

    onChange({ ...data, conversions: results });
  };

  const now = new Date();
  const currentTimeStr = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Time</label>
          <input
            type="time"
            value={inputTime}
            onChange={(e) => onChange({ ...data, inputTime: e.target.value })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Source Timezone</label>
          <select
            value={sourceTimezone}
            onChange={(e) => onChange({ ...data, sourceTimezone: e.target.value })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          >
            {timezones.map(tz => (
              <option key={tz.id} value={tz.id}>{tz.label}</option>
            ))}
          </select>
        </div>
      </div>

      <div className="flex gap-2">
        <button
          onClick={handleConvert}
          disabled={!inputTime}
          className="flex-1 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white rounded text-sm"
        >
          Convert
        </button>
        <button
          onClick={() => onChange({ ...data, inputTime: currentTimeStr })}
          className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded text-sm"
        >
          Now
        </button>
      </div>

      {conversions.length > 0 && (
        <div className="space-y-1 max-h-64 overflow-y-auto">
          {conversions.map((conv, idx) => (
            <div
              key={idx}
              className={`flex justify-between items-center p-2 rounded text-sm ${
                timezones[idx]?.id === sourceTimezone
                  ? 'bg-blue-900/30 border border-blue-700'
                  : 'bg-[#1a1a2e]'
              }`}
            >
              <div>
                <span className="text-gray-300">{conv.timezone}</span>
                <span className="text-gray-500 text-xs ml-2">{conv.offset}</span>
              </div>
              <div className="font-mono text-green-400">{conv.time}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export class TimezoneConverterTool {
  static Component = TimezoneConverter;
}
