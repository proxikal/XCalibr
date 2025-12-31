import React from 'react';
import type { DomSnapshotData, SnapshotEntry } from './tool-types';

const MAX_SNAPSHOTS = 10;

const formatTimestamp = (ts: number): string => {
  const date = new Date(ts);
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
};

const computeSimpleDiff = (oldHtml: string, newHtml: string): { type: 'same' | 'added' | 'removed'; line: string }[] => {
  const oldLines = oldHtml.split('\n');
  const newLines = newHtml.split('\n');
  const result: { type: 'same' | 'added' | 'removed'; line: string }[] = [];

  const oldSet = new Set(oldLines);
  const newSet = new Set(newLines);

  // Find removed lines (in old but not in new)
  for (const line of oldLines) {
    if (!newSet.has(line)) {
      result.push({ type: 'removed', line });
    }
  }

  // Find added lines (in new but not in old)
  for (const line of newLines) {
    if (!oldSet.has(line)) {
      result.push({ type: 'added', line });
    }
  }

  // If no diff, show first few lines as same
  if (result.length === 0) {
    for (let i = 0; i < Math.min(5, newLines.length); i++) {
      result.push({ type: 'same', line: newLines[i] });
    }
  }

  return result.slice(0, 50); // Limit diff display
};

const DomSnapshotToolComponent = ({
  data,
  onChange,
  onRefresh
}: {
  data: DomSnapshotData | undefined;
  onChange: (next: DomSnapshotData) => void;
  onRefresh: () => Promise<void>;
}) => {
  const html = data?.html ?? '';
  const snapshots = data?.snapshots ?? [];
  const showRaw = data?.showRaw ?? false;
  const includeShadowDom = data?.includeShadowDom ?? false;
  const selectedIndex = data?.selectedIndex ?? -1;
  const compareIndex = data?.compareIndex ?? null;
  const showDiff = data?.showDiff ?? false;

  const takeSnapshot = () => {
    const newSnapshot: SnapshotEntry = {
      html,
      timestamp: Date.now(),
      label: `Snapshot ${snapshots.length + 1}`,
      raw: showRaw,
      includeShadowDom
    };

    const newSnapshots = [...snapshots, newSnapshot].slice(-MAX_SNAPSHOTS);
    onChange({
      ...data,
      snapshots: newSnapshots,
      selectedIndex: newSnapshots.length - 1
    });
  };

  const selectSnapshot = (index: number) => {
    onChange({
      ...data,
      selectedIndex: index,
      compareIndex: null,
      showDiff: false
    });
  };

  const toggleCompare = (index: number) => {
    if (compareIndex === index) {
      onChange({ ...data, compareIndex: null, showDiff: false });
    } else {
      onChange({ ...data, compareIndex: index, showDiff: true });
    }
  };

  const deleteSnapshot = (index: number) => {
    const newSnapshots = snapshots.filter((_, i) => i !== index);
    let newSelectedIndex = selectedIndex;
    let newCompareIndex = compareIndex;

    if (selectedIndex === index) {
      newSelectedIndex = Math.max(0, newSnapshots.length - 1);
    } else if (selectedIndex > index) {
      newSelectedIndex = selectedIndex - 1;
    }

    if (compareIndex === index) {
      newCompareIndex = null;
    } else if (compareIndex !== null && compareIndex > index) {
      newCompareIndex = compareIndex - 1;
    }

    onChange({
      ...data,
      snapshots: newSnapshots,
      selectedIndex: newSnapshots.length > 0 ? newSelectedIndex : -1,
      compareIndex: newCompareIndex,
      showDiff: newCompareIndex !== null
    });
  };

  const copySnapshot = () => {
    const content = selectedIndex >= 0 && snapshots[selectedIndex]
      ? snapshots[selectedIndex].html
      : html;
    navigator.clipboard.writeText(content);
  };

  const downloadSnapshot = () => {
    const content = selectedIndex >= 0 && snapshots[selectedIndex]
      ? snapshots[selectedIndex].html
      : html;
    const blob = new Blob([content], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `snapshot-${window.location.hostname}-${new Date().toISOString().split('T')[0]}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const selectedSnapshot = selectedIndex >= 0 ? snapshots[selectedIndex] : null;
  const compareSnapshot = compareIndex !== null ? snapshots[compareIndex] : null;

  const diffResult = showDiff && selectedSnapshot && compareSnapshot
    ? computeSimpleDiff(compareSnapshot.html, selectedSnapshot.html)
    : [];

  const currentHtml = selectedSnapshot?.html ?? html;
  const lineCount = currentHtml.split('\n').length;
  const charCount = currentHtml.length;

  return (
    <div className="flex flex-col h-full space-y-2">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="text-xs text-slate-200">DOM Snapshot</div>
        <div className="flex gap-1">
          <button
            type="button"
            onClick={() => onChange({ ...data, includeShadowDom: !includeShadowDom })}
            className={`rounded px-2 py-1 text-[9px] border transition-colors ${
              includeShadowDom
                ? 'bg-purple-500/20 border-purple-500/50 text-purple-300'
                : 'bg-slate-800 border-slate-700 text-slate-400'
            }`}
            title="Include Shadow DOM content"
          >
            Shadow
          </button>
          <button
            type="button"
            onClick={() => onChange({ ...data, showRaw: !showRaw })}
            className={`rounded px-2 py-1 text-[9px] border transition-colors ${
              showRaw
                ? 'bg-amber-500/20 border-amber-500/50 text-amber-300'
                : 'bg-slate-800 border-slate-700 text-slate-400'
            }`}
            title="Raw HTML (no sanitization)"
          >
            Raw
          </button>
          <button
            type="button"
            onClick={onRefresh}
            className="rounded bg-slate-800 px-2 py-1 text-[9px] text-slate-300 hover:bg-slate-700 transition-colors"
          >
            Capture
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="text-[9px] text-slate-500">
        {lineCount} lines, {charCount.toLocaleString()} chars
        {selectedSnapshot && (
          <span className="ml-2 text-slate-400">
            @ {formatTimestamp(selectedSnapshot.timestamp)}
          </span>
        )}
      </div>

      {/* Snapshot History */}
      {snapshots.length > 0 && (
        <div className="space-y-1">
          <div className="flex items-center justify-between">
            <div className="text-[9px] text-slate-400 font-medium">History ({snapshots.length})</div>
            <button
              type="button"
              onClick={takeSnapshot}
              className="text-[8px] text-blue-400 hover:text-blue-300"
            >
              + Save Current
            </button>
          </div>
          <div className="flex flex-wrap gap-1 max-h-16 overflow-y-auto">
            {snapshots.map((snapshot, idx) => (
              <div
                key={snapshot.timestamp}
                className={`flex items-center gap-1 rounded px-1.5 py-0.5 text-[8px] border cursor-pointer transition-colors ${
                  selectedIndex === idx
                    ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-300'
                    : compareIndex === idx
                    ? 'bg-amber-500/20 border-amber-500/50 text-amber-300'
                    : 'bg-slate-800 border-slate-700 text-slate-400 hover:bg-slate-700'
                }`}
              >
                <span onClick={() => selectSnapshot(idx)}>
                  {formatTimestamp(snapshot.timestamp)}
                </span>
                {selectedIndex !== idx && (
                  <button
                    type="button"
                    onClick={() => toggleCompare(idx)}
                    className={`ml-1 px-1 rounded ${
                      compareIndex === idx
                        ? 'bg-amber-500/30 text-amber-200'
                        : 'bg-slate-700 text-slate-400 hover:bg-slate-600'
                    }`}
                    title="Compare with selected"
                  >
                    cmp
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => deleteSnapshot(idx)}
                  className="ml-1 text-slate-500 hover:text-rose-400"
                  title="Delete snapshot"
                >
                  x
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Save Snapshot Button (when no history) */}
      {snapshots.length === 0 && html && (
        <button
          type="button"
          onClick={takeSnapshot}
          className="w-full rounded bg-emerald-600/20 border border-emerald-500/50 px-2 py-1 text-[10px] text-emerald-300 hover:bg-emerald-600/30 transition-colors"
        >
          Save to History
        </button>
      )}

      {/* Diff View */}
      {showDiff && diffResult.length > 0 && (
        <div className="rounded bg-slate-900 border border-slate-800 p-2 max-h-32 overflow-y-auto">
          <div className="text-[9px] text-slate-400 mb-1">
            Diff: #{compareIndex !== null ? compareIndex + 1 : '-'} vs #{selectedIndex + 1}
          </div>
          <div className="font-mono text-[8px] space-y-0.5">
            {diffResult.map((item, idx) => (
              <div
                key={idx}
                className={`px-1 rounded ${
                  item.type === 'added'
                    ? 'bg-emerald-500/20 text-emerald-300'
                    : item.type === 'removed'
                    ? 'bg-rose-500/20 text-rose-300'
                    : 'text-slate-500'
                }`}
              >
                <span className="mr-1">
                  {item.type === 'added' ? '+' : item.type === 'removed' ? '-' : ' '}
                </span>
                <span className="truncate">{item.line.slice(0, 80)}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* HTML Preview */}
      <textarea
        value={currentHtml}
        readOnly
        className="flex-1 w-full rounded bg-slate-900 text-slate-300 text-[10px] font-mono px-2 py-2 border border-slate-800 focus:outline-none min-h-[120px] resize-none"
        placeholder="Capture DOM to see HTML..."
      />

      {/* Action Buttons */}
      <div className="flex gap-1">
        <button
          type="button"
          onClick={copySnapshot}
          disabled={!currentHtml}
          className="flex-1 rounded bg-slate-800 px-2 py-1.5 text-[10px] text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
        >
          Copy
        </button>
        <button
          type="button"
          onClick={downloadSnapshot}
          disabled={!currentHtml}
          className="flex-1 rounded bg-slate-800 px-2 py-1.5 text-[10px] text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
        >
          Download
        </button>
      </div>
    </div>
  );
};

export class DomSnapshotTool {
  static Component = DomSnapshotToolComponent;
}
