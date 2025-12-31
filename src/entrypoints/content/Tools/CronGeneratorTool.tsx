import React, { useEffect, useCallback } from 'react';
import type { CronGeneratorData } from './tool-types';

const PRESETS = [
  { label: 'Every minute', cron: '* * * * *' },
  { label: 'Every 5 minutes', cron: '*/5 * * * *' },
  { label: 'Every hour', cron: '0 * * * *' },
  { label: 'Every day at midnight', cron: '0 0 * * *' },
  { label: 'Every Monday', cron: '0 0 * * 1' },
  { label: 'First of month', cron: '0 0 1 * *' },
];

const describeCron = (minute: string, hour: string, dom: string, month: string, dow: string): string => {
  const parts: string[] = [];

  if (minute === '*') parts.push('every minute');
  else if (minute.startsWith('*/')) parts.push(`every ${minute.slice(2)} minutes`);
  else parts.push(`at minute ${minute}`);

  if (hour !== '*') {
    if (hour.startsWith('*/')) parts.push(`every ${hour.slice(2)} hours`);
    else parts.push(`at ${hour}:00`);
  }

  if (dom !== '*') parts.push(`on day ${dom}`);
  if (month !== '*') parts.push(`in month ${month}`);
  if (dow !== '*') parts.push(`on weekday ${dow}`);

  return parts.join(', ');
};

type Props = {
  data: CronGeneratorData | undefined;
  onChange: (next: CronGeneratorData) => void;
};

const CronGeneratorToolComponent = ({ data, onChange }: Props) => {
  const minute = data?.minute ?? '*';
  const hour = data?.hour ?? '*';
  const dayOfMonth = data?.dayOfMonth ?? '*';
  const month = data?.month ?? '*';
  const dayOfWeek = data?.dayOfWeek ?? '*';

  const expression = `${minute} ${hour} ${dayOfMonth} ${month} ${dayOfWeek}`;
  const description = describeCron(minute, hour, dayOfMonth, month, dayOfWeek);

  const handlePreset = useCallback((cron: string) => {
    const [m, h, dom, mon, dow] = cron.split(' ');
    onChange({ minute: m, hour: h, dayOfMonth: dom, month: mon, dayOfWeek: dow });
  }, [onChange]);

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Cron Expression Generator</div>

      <div className="flex flex-wrap gap-1">
        {PRESETS.map((p) => (
          <button
            key={p.cron}
            type="button"
            onClick={() => handlePreset(p.cron)}
            className="rounded px-2 py-1 text-[10px] bg-slate-800 text-slate-300 hover:bg-slate-700"
          >
            {p.label}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-5 gap-2">
        {[
          { label: 'Min', value: minute, key: 'minute' },
          { label: 'Hour', value: hour, key: 'hour' },
          { label: 'Day', value: dayOfMonth, key: 'dayOfMonth' },
          { label: 'Month', value: month, key: 'month' },
          { label: 'Weekday', value: dayOfWeek, key: 'dayOfWeek' },
        ].map((f) => (
          <div key={f.key} className="space-y-1">
            <div className="text-[10px] text-slate-400 text-center">{f.label}</div>
            <input
              type="text"
              value={f.value}
              onChange={(e) => onChange({ ...data, [f.key]: e.target.value })}
              className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1.5 border border-slate-700 focus:outline-none focus:border-emerald-500 font-mono text-center"
            />
          </div>
        ))}
      </div>

      <div className="bg-slate-800 rounded p-3 text-center">
        <div className="text-emerald-400 font-mono text-lg">{expression}</div>
        <div className="text-[10px] text-slate-400 mt-1">{description}</div>
      </div>

      <div className="text-[10px] text-slate-500">
        Use * for any, */n for every n, specific values, or ranges (1-5).
      </div>
    </div>
  );
};

export class CronGeneratorTool {
  static Component = CronGeneratorToolComponent;
}
