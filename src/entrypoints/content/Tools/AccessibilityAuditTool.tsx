import React from 'react';
import type {
  AccessibilityAuditData
} from './tool-types';

const AccessibilityAuditToolComponent = ({
  data,
  onRun
}: {
  data: AccessibilityAuditData | undefined;
  onRun: () => void;
}) => {
  const issues = data?.issues ?? [];
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-slate-200">Accessibility Audit</div>
        <button
          type="button"
          onClick={onRun}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Run Audit
        </button>
      </div>
      <div className="rounded border border-slate-800 bg-slate-900/60 p-3 text-[11px] text-slate-300 max-h-32 overflow-y-auto no-scrollbar">
        {issues.length === 0 ? 'No audit results yet.' : issues.join('\n')}
      </div>
    </div>
  );
};
export class AccessibilityAuditTool {
  static Component = AccessibilityAuditToolComponent;
}
