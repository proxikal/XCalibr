import React, { useState } from 'react';
import {
  fuzzPayloads,
  fuzzCategories,
  type FuzzCategory,
  type PayloadApplicationResult
} from './helpers';
import type {
  FormFuzzerData
} from './tool-types';

const PAYLOADS_PER_PAGE = 8;

const FormFuzzerToolComponent = ({
  data,
  onChange,
  onRefresh,
  onApply
}: {
  data: FormFuzzerData | undefined;
  onChange: (next: FormFuzzerData) => void;
  onRefresh: () => Promise<void>;
  onApply: (formIndex: number, payload: string) => Promise<PayloadApplicationResult>;
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const [activeCategory, setActiveCategory] = useState<FuzzCategory>('xss');
  const [page, setPage] = useState(0);
  const [showResults, setShowResults] = useState(false);

  const selectedPayload = data?.selectedPayload ?? '';
  const selectedFormIndex = data?.selectedFormIndex ?? 0;
  const forms = data?.forms ?? [];
  const customPayload = data?.customPayload ?? '';
  const lastResult = data?.lastResult;

  const categoryPayloads = fuzzPayloads[activeCategory];
  const totalPages = Math.ceil(categoryPayloads.length / PAYLOADS_PER_PAGE);
  const paginatedPayloads = categoryPayloads.slice(
    page * PAYLOADS_PER_PAGE,
    (page + 1) * PAYLOADS_PER_PAGE
  );

  const update = (next: Partial<FormFuzzerData>) =>
    onChange({
      selectedPayload,
      selectedFormIndex,
      forms,
      customPayload,
      status: data?.status,
      ...next
    });

  const handleRefresh = async () => {
    setIsLoading(true);
    await onRefresh();
    setIsLoading(false);
  };

  const handleApply = async () => {
    const payload =
      selectedPayload === '__custom__' ? customPayload : selectedPayload;
    if (!payload) {
      update({ status: 'Choose a payload to apply.', lastResult: undefined });
      return;
    }
    const result = await onApply(selectedFormIndex, payload);
    const status = !result.formFound
      ? 'Form not found.'
      : result.success
        ? `Payload injected into ${result.appliedCount} field${result.appliedCount !== 1 ? 's' : ''}.`
        : 'No injectable fields found.';
    update({ status, lastResult: result });
    setShowResults(true);
  };

  const handleCategoryChange = (category: FuzzCategory) => {
    setActiveCategory(category);
    setPage(0);
  };

  const getCategoryStyle = (category: FuzzCategory) => {
    const isActive = activeCategory === category;
    switch (category) {
      case 'xss':
        return isActive
          ? 'bg-amber-500/10 border-amber-500/50 text-amber-300'
          : 'bg-slate-800 border-slate-700 text-slate-400';
      case 'sqli':
        return isActive
          ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
          : 'bg-slate-800 border-slate-700 text-slate-400';
      case 'lfi':
        return isActive
          ? 'bg-emerald-500/10 border-emerald-500/50 text-emerald-300'
          : 'bg-slate-800 border-slate-700 text-slate-400';
      case 'ssti':
        return isActive
          ? 'bg-purple-500/10 border-purple-500/50 text-purple-300'
          : 'bg-slate-800 border-slate-700 text-slate-400';
      case 'cmd':
        return isActive
          ? 'bg-rose-500/10 border-rose-500/50 text-rose-300'
          : 'bg-slate-800 border-slate-700 text-slate-400';
      case 'xxe':
        return isActive
          ? 'bg-cyan-500/10 border-cyan-500/50 text-cyan-300'
          : 'bg-slate-800 border-slate-700 text-slate-400';
      default:
        return 'bg-slate-800 border-slate-700 text-slate-400';
    }
  };

  return (
    <div className="flex flex-col h-full">
      {/* Header - fixed */}
      <div className="flex items-center justify-between mb-2 flex-shrink-0">
        <div className="text-xs text-slate-200">Form Fuzzer</div>
        <button
          type="button"
          onClick={handleRefresh}
          disabled={isLoading}
          className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors disabled:opacity-50"
        >
          {isLoading ? 'Scanning...' : 'Scan Forms'}
        </button>
      </div>

      <div className="text-[10px] text-slate-500 mb-2 flex-shrink-0">
        {forms.length} form{forms.length !== 1 ? 's' : ''} detected
      </div>

      {/* Forms section - scrollable if many forms, max height limited */}
      {forms.length > 0 && (
        <div className="mb-2 flex-shrink-0">
          <div className="text-[9px] uppercase tracking-widest text-slate-500 mb-1">Forms</div>
          <div className="flex flex-wrap gap-1 max-h-16 overflow-y-auto">
            {forms.map((form) => (
              <button
                key={form.index}
                type="button"
                onClick={() => update({ selectedFormIndex: form.index })}
                className={`rounded px-2 py-1 text-[10px] border transition-colors ${
                  selectedFormIndex === form.index
                    ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                    : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                }`}
              >
                {form.method} #{form.index}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Categories - fixed */}
      <div className="mb-2 flex-shrink-0">
        <div className="text-[9px] uppercase tracking-widest text-slate-500 mb-1">Category</div>
        <div className="flex flex-wrap gap-1">
          {fuzzCategories.map((cat) => (
            <button
              key={cat.key}
              type="button"
              onClick={() => handleCategoryChange(cat.key)}
              className={`rounded px-2 py-1 text-[10px] border transition-colors ${getCategoryStyle(cat.key)}`}
            >
              <span className="mr-1">{cat.icon}</span>
              {cat.label} ({fuzzPayloads[cat.key].length})
            </button>
          ))}
        </div>
      </div>

      {/* Payload list - flexible, takes remaining space */}
      <div className="flex-1 overflow-y-auto min-h-0 mb-2">
        <div className="space-y-1">
          {paginatedPayloads.map((payload, idx) => (
            <button
              key={`${activeCategory}-${page}-${idx}`}
              type="button"
              onClick={() => update({ selectedPayload: payload })}
              className={`w-full rounded px-2 py-1.5 text-[10px] border text-left transition-colors font-mono truncate ${
                selectedPayload === payload
                  ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
              }`}
              title={payload}
            >
              {payload}
            </button>
          ))}
          <button
            type="button"
            onClick={() => update({ selectedPayload: '__custom__' })}
            className={`w-full rounded px-2 py-1.5 text-[10px] border text-left transition-colors ${
              selectedPayload === '__custom__'
                ? 'bg-purple-500/10 border-purple-500/50 text-purple-300'
                : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
            }`}
          >
            ✏️ Custom Payload
          </button>
        </div>
      </div>

      {/* Pagination - fixed at bottom */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mb-2 pt-2 border-t border-slate-700 flex-shrink-0">
          <button
            type="button"
            onClick={() => setPage(Math.max(0, page - 1))}
            disabled={page === 0}
            className="text-[10px] text-slate-400 hover:text-slate-200 disabled:opacity-30"
          >
            ← Prev
          </button>
          <span className="text-[10px] text-slate-500">
            {page + 1} / {totalPages}
          </span>
          <button
            type="button"
            onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
            disabled={page >= totalPages - 1}
            className="text-[10px] text-slate-400 hover:text-slate-200 disabled:opacity-30"
          >
            Next →
          </button>
        </div>
      )}

      {/* Custom payload input - fixed */}
      {selectedPayload === '__custom__' && (
        <input
          type="text"
          value={customPayload}
          onChange={(event) => update({ customPayload: event.target.value })}
          className="w-full rounded bg-slate-800 text-slate-200 text-[11px] px-2 py-1.5 border border-slate-700 focus:outline-none focus:border-blue-500 mb-2 font-mono flex-shrink-0"
          placeholder="Enter custom payload"
        />
      )}

      {/* Status message - fixed */}
      {data?.status && (
        <div className="text-[10px] text-slate-500 mb-2 flex-shrink-0">{data.status}</div>
      )}

      {/* Results panel - collapsible */}
      {lastResult && lastResult.formFound && (
        <div className="mb-2 flex-shrink-0 border border-slate-700 rounded overflow-hidden">
          <button
            type="button"
            onClick={() => setShowResults(!showResults)}
            className="w-full flex items-center justify-between px-2 py-1.5 bg-slate-800 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
          >
            <span>
              {lastResult.success ? '✓' : '⚠'} Results: {lastResult.appliedCount}/{lastResult.totalFields} fields
            </span>
            <span className="text-slate-500">{showResults ? '▼' : '▶'}</span>
          </button>
          {showResults && (
            <div className="max-h-28 overflow-y-auto bg-slate-900/50">
              {lastResult.fields.map((field, idx) => (
                <div
                  key={idx}
                  className={`flex items-center gap-2 px-2 py-1 text-[9px] border-t border-slate-800 ${
                    field.applied ? 'text-emerald-400' : 'text-slate-500'
                  }`}
                >
                  <span className={field.applied ? 'text-emerald-500' : 'text-amber-500'}>
                    {field.applied ? '✓' : '○'}
                  </span>
                  <span className="font-mono truncate flex-1" title={field.name}>
                    {field.name}
                  </span>
                  <span className="text-slate-600">{field.type}</span>
                  {field.reason && (
                    <span className="text-slate-600 truncate max-w-[80px]" title={field.reason}>
                      {field.reason.replace('Skipped: ', '')}
                    </span>
                  )}
                </div>
              ))}
              {lastResult.fields.length === 0 && (
                <div className="px-2 py-2 text-[9px] text-slate-500 text-center">
                  No fields in this form
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Apply button - fixed at bottom */}
      <button
        type="button"
        onClick={handleApply}
        disabled={forms.length === 0 || (!selectedPayload || (selectedPayload === '__custom__' && !customPayload))}
        className="w-full rounded bg-blue-600 px-2 py-1.5 text-[11px] text-white hover:bg-blue-500 transition-colors disabled:opacity-50 flex-shrink-0"
      >
        Apply Payload
      </button>
    </div>
  );
};
export class FormFuzzerTool {
  static Component = FormFuzzerToolComponent;
}
