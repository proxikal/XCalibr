import React, { useState } from 'react';
import type {
  TechFingerprintData
} from './tool-types';

const TechFingerprintToolComponent = ({
  data,
  onRefresh
}: {
  data: TechFingerprintData | undefined;
  onRefresh: () => Promise<void>;
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const findings = data?.findings ?? [];

  const handleRefresh = async () => {
    setIsLoading(true);
    await onRefresh();
    setIsLoading(false);
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-xs text-slate-200">Tech Fingerprint</div>
          <div className="text-[11px] text-slate-500">{data?.url ?? ''}</div>
        </div>
        <button
          type="button"
          onClick={handleRefresh}
          disabled={isLoading}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors disabled:opacity-50"
        >
          {isLoading ? 'Scanning...' : 'Scan'}
        </button>
      </div>
      {findings.length === 0 ? (
        <div className="text-[11px] text-slate-500">
          No signals yet. Run a scan.
        </div>
      ) : (
        findings.map((finding, index) => (
          <div
            key={`${finding.label}-${finding.value}-${index}`}
            className="rounded border border-slate-800 bg-slate-800/60 px-2 py-1 text-[11px] text-slate-300"
          >
            <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
              {finding.label}
            </div>
            <div className="break-words">{finding.value}</div>
          </div>
        ))
      )}
    </div>
  );
};
export class TechFingerprintTool {
  static Component = TechFingerprintToolComponent;
}
