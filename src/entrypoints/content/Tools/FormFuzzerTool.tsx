import React, { useState, useMemo, useEffect, useCallback } from 'react';
import {
  fuzzPayloads,
  fuzzCategories,
  type FuzzCategory,
  type PayloadApplicationResult
} from './helpers';
import type {
  FormFuzzerData,
  FieldPayloadMapping,
  DomMutation
} from './tool-types';

const PAYLOADS_PER_PAGE = 10;

const CSRF_PATTERNS = [
  /csrf/i,
  /xsrf/i,
  /token/i,
  /_token/i,
  /authenticity/i,
  /nonce/i,
  /antiforgery/i
];

const isCsrfField = (name: string): boolean => {
  return CSRF_PATTERNS.some(pattern => pattern.test(name));
};

const FormFuzzerToolComponent = ({
  data,
  onChange,
  onRefresh,
  onApply,
  onSubmit
}: {
  data: FormFuzzerData | undefined;
  onChange: (next: FormFuzzerData) => void;
  onRefresh: () => Promise<void>;
  onApply: (formIndex: number, payload: string, fieldMappings?: FieldPayloadMapping[], preserveCsrf?: boolean) => Promise<PayloadApplicationResult>;
  onSubmit?: (formIndex: number) => Promise<{ status?: number; body?: string; error?: string }>;
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const [activeCategory, setActiveCategory] = useState<FuzzCategory>('xss');
  const [page, setPage] = useState(0);
  const [showResults, setShowResults] = useState(false);
  const [showFieldMapping, setShowFieldMapping] = useState(false);
  const [mutationObserver, setMutationObserver] = useState<MutationObserver | null>(null);

  const selectedPayload = data?.selectedPayload ?? '';
  const selectedFormIndex = data?.selectedFormIndex ?? 0;
  const forms = data?.forms ?? [];
  const customPayload = data?.customPayload ?? '';
  const lastResult = data?.lastResult;
  const submitMode = data?.submitMode ?? 'inject';
  const preserveCsrf = data?.preserveCsrf ?? true;
  const fieldMappings = data?.fieldMappings ?? [];
  const domMutations = data?.domMutations ?? [];
  const lastResponse = data?.lastResponse;
  const validationErrors = data?.validationErrors ?? [];
  const isSubmitting = data?.isSubmitting ?? false;

  const selectedForm = forms.find(f => f.index === selectedFormIndex);

  const categoryPayloads = fuzzPayloads[activeCategory];
  const totalPages = Math.ceil(categoryPayloads.length / PAYLOADS_PER_PAGE);
  const paginatedPayloads = categoryPayloads.slice(
    page * PAYLOADS_PER_PAGE,
    (page + 1) * PAYLOADS_PER_PAGE
  );

  const update = useCallback((next: Partial<FormFuzzerData>) =>
    onChange({
      selectedPayload,
      selectedFormIndex,
      forms,
      customPayload,
      status: data?.status,
      submitMode,
      preserveCsrf,
      fieldMappings,
      domMutations,
      lastResponse,
      validationErrors,
      isSubmitting,
      ...next
    }), [data, onChange, selectedPayload, selectedFormIndex, forms, customPayload, submitMode, preserveCsrf, fieldMappings, domMutations, lastResponse, validationErrors, isSubmitting]);

  // Initialize field mappings when form is selected
  useEffect(() => {
    if (selectedForm && fieldMappings.length === 0) {
      const initialMappings: FieldPayloadMapping[] = selectedForm.inputs.map(input => ({
        fieldName: input.name,
        payload: '',
        enabled: !isCsrfField(input.name) && input.type !== 'hidden'
      }));
      update({ fieldMappings: initialMappings });
    }
  }, [selectedForm, fieldMappings.length, update]);

  // Start DOM mutation observer
  const startMutationObserver = useCallback(() => {
    if (mutationObserver) {
      mutationObserver.disconnect();
    }

    const observer = new MutationObserver((mutations) => {
      const newMutations: DomMutation[] = mutations.slice(0, 20).map(m => ({
        type: m.type as DomMutation['type'],
        target: (m.target as Element).tagName?.toLowerCase() || 'unknown',
        attributeName: m.attributeName || undefined,
        oldValue: m.oldValue || undefined,
        newValue: m.type === 'attributes' && m.target instanceof Element
          ? m.target.getAttribute(m.attributeName || '') || undefined
          : undefined,
        timestamp: Date.now()
      }));

      if (newMutations.length > 0) {
        update({ domMutations: [...(domMutations || []).slice(-30), ...newMutations] });
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeOldValue: true
    });

    setMutationObserver(observer);
  }, [mutationObserver, domMutations, update]);

  const stopMutationObserver = useCallback(() => {
    if (mutationObserver) {
      mutationObserver.disconnect();
      setMutationObserver(null);
    }
  }, [mutationObserver]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (mutationObserver) {
        mutationObserver.disconnect();
      }
    };
  }, [mutationObserver]);

  const handleRefresh = async () => {
    setIsLoading(true);
    await onRefresh();
    setIsLoading(false);
  };

  const handleApply = async () => {
    const payload =
      selectedPayload === '__custom__' ? customPayload : selectedPayload;
    if (!payload && !fieldMappings.some(m => m.payload)) {
      update({ status: 'Choose a payload to apply.', lastResult: undefined });
      return;
    }

    // Start observing DOM mutations
    startMutationObserver();
    update({ domMutations: [] });

    const result = await onApply(selectedFormIndex, payload, fieldMappings, preserveCsrf);
    const status = !result.formFound
      ? 'Form not found.'
      : result.success
        ? `Payload injected into ${result.appliedCount} field${result.appliedCount !== 1 ? 's' : ''}.`
        : 'No injectable fields found.';
    update({ status, lastResult: result });
    setShowResults(true);

    // Stop observing after a short delay to capture immediate reactions
    setTimeout(() => stopMutationObserver(), 1000);

    // Auto-submit form when in submit mode and injection was successful
    if (submitMode === 'submit' && result.success && result.appliedCount > 0 && onSubmit) {
      // Small delay to allow DOM to update before submitting
      setTimeout(async () => {
        update({ isSubmitting: true, status: 'Submitting form...' });
        try {
          const response = await onSubmit(selectedFormIndex);
          update({
            isSubmitting: false,
            lastResponse: {
              status: response.status,
              body: response.body,
              error: response.error
            },
            status: response.error
              ? `Error: ${response.error}`
              : `Injected & submitted. Response: ${response.status}`
          });
        } catch (error) {
          update({
            isSubmitting: false,
            lastResponse: { error: String(error) },
            status: `Error: ${error}`
          });
        }
      }, 100);
    }
  };

  const handleSubmitForm = async () => {
    if (!onSubmit) {
      update({ status: 'Submit not supported in this context.' });
      return;
    }

    update({ isSubmitting: true, status: 'Submitting form...' });

    try {
      const response = await onSubmit(selectedFormIndex);
      update({
        isSubmitting: false,
        lastResponse: {
          status: response.status,
          body: response.body,
          error: response.error
        },
        status: response.error
          ? `Error: ${response.error}`
          : `Response: ${response.status}`
      });
    } catch (error) {
      update({
        isSubmitting: false,
        lastResponse: { error: String(error) },
        status: `Error: ${error}`
      });
    }
  };

  const handleCategoryChange = (category: FuzzCategory) => {
    setActiveCategory(category);
    setPage(0);
  };

  const handleFieldMappingChange = (fieldName: string, updates: Partial<FieldPayloadMapping>) => {
    const updatedMappings = fieldMappings.map(m =>
      m.fieldName === fieldName ? { ...m, ...updates } : m
    );
    update({ fieldMappings: updatedMappings });
  };

  const handleApplyPayloadToAll = () => {
    const payload = selectedPayload === '__custom__' ? customPayload : selectedPayload;
    if (!payload) return;

    const updatedMappings = fieldMappings.map(m => ({
      ...m,
      payload: m.enabled ? payload : m.payload
    }));
    update({ fieldMappings: updatedMappings });
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

  const getModeStyle = (mode: string) => {
    const isActive = submitMode === mode;
    return isActive
      ? 'bg-blue-500/20 border-blue-500/50 text-blue-300'
      : 'bg-slate-800 border-slate-700 text-slate-500 hover:border-slate-600 hover:text-slate-400';
  };

  return (
    <div className="flex flex-col h-full p-1">
      {/* Header row with title, mode buttons, and scan button */}
      <div className="flex items-center gap-2 mb-3 flex-shrink-0">
        <div className="text-sm text-slate-200 font-medium">Form Fuzzer</div>
        <div className="flex gap-1 mx-2">
          {(['inject', 'preview', 'submit'] as const).map(mode => (
            <button
              key={mode}
              type="button"
              onClick={() => update({ submitMode: mode })}
              className={`rounded px-2 py-0.5 text-[9px] border transition-colors ${getModeStyle(mode)}`}
            >
              {mode === 'inject' ? '💉' : mode === 'preview' ? '👁' : '📤'}
              <span className="ml-1">{mode.charAt(0).toUpperCase() + mode.slice(1)}</span>
            </button>
          ))}
        </div>
        <button
          type="button"
          onClick={handleRefresh}
          disabled={isLoading}
          className="rounded bg-blue-600 px-3 py-1 text-[10px] text-white hover:bg-blue-500 transition-colors disabled:opacity-50 ml-auto"
        >
          {isLoading ? 'Scanning...' : 'Scan Forms'}
        </button>
      </div>

      {/* Forms count */}
      <div className="text-[11px] text-slate-500 mb-2 flex-shrink-0">
        {forms.length} form{forms.length !== 1 ? 's' : ''} detected
      </div>

      {/* Forms section */}
      {forms.length > 0 && (
        <div className="mb-2 flex-shrink-0">
          <div className="flex flex-wrap gap-1 max-h-16 overflow-y-auto">
            {forms.map((form) => (
              <button
                key={form.index}
                type="button"
                onClick={() => {
                  update({
                    selectedFormIndex: form.index,
                    fieldMappings: form.inputs.map(input => ({
                      fieldName: input.name,
                      payload: '',
                      enabled: !isCsrfField(input.name) && input.type !== 'hidden'
                    }))
                  });
                }}
                className={`rounded px-1.5 py-0.5 text-[9px] border transition-colors ${
                  selectedFormIndex === form.index
                    ? 'bg-blue-500/20 border-blue-500/50 text-blue-300'
                    : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                }`}
              >
                {form.method} #{form.index} ({form.inputs.length})
              </button>
            ))}
          </div>
        </div>
      )}

      {/* CSRF Token Preservation + Per-Field Mapping on same row */}
      {selectedForm && (
        <div className="flex items-center gap-3 mb-2 flex-shrink-0">
          {selectedForm.inputs.some(i => isCsrfField(i.name) || i.isCsrf) && (
            <label className="flex items-center gap-1.5 text-[10px] text-slate-400">
              <input
                type="checkbox"
                checked={preserveCsrf}
                onChange={(e) => update({ preserveCsrf: e.target.checked })}
                className="rounded border-slate-600 bg-slate-800 text-blue-500 w-3 h-3"
              />
              <span>Preserve CSRF</span>
            </label>
          )}
          <button
            type="button"
            onClick={() => setShowFieldMapping(!showFieldMapping)}
            className="flex items-center gap-1 text-[10px] text-slate-400 hover:text-slate-300"
          >
            <span className="text-[9px]">{showFieldMapping ? '▼' : '▶'}</span>
            <span>🎯 Per-Field Mapping ({fieldMappings.filter(m => m.enabled).length})</span>
          </button>
        </div>
      )}

      {/* Field Mapping Grid - expands here, above categories */}
      {showFieldMapping && selectedForm && (
        <div className="mb-3 flex-shrink-0 max-h-40 overflow-y-auto border border-slate-700 rounded-lg">
          <table className="w-full text-[10px]">
            <thead className="bg-slate-800 sticky top-0">
              <tr>
                <th className="px-2 py-1.5 text-left text-slate-500 w-8">✓</th>
                <th className="px-2 py-1.5 text-left text-slate-500">Field</th>
                <th className="px-2 py-1.5 text-left text-slate-500 w-16">Type</th>
                <th className="px-2 py-1.5 text-left text-slate-500">Payload Override</th>
              </tr>
            </thead>
            <tbody>
              {fieldMappings.map((mapping, idx) => {
                const input = selectedForm.inputs.find(i => i.name === mapping.fieldName);
                const isToken = isCsrfField(mapping.fieldName);
                return (
                  <tr key={idx} className={`border-t border-slate-800 ${isToken ? 'bg-amber-500/5' : ''}`}>
                    <td className="px-2 py-1.5">
                      <input
                        type="checkbox"
                        checked={mapping.enabled}
                        onChange={(e) => handleFieldMappingChange(mapping.fieldName, { enabled: e.target.checked })}
                        className="rounded border-slate-600 bg-slate-800 text-blue-500"
                        disabled={isToken && preserveCsrf}
                      />
                    </td>
                    <td className="px-2 py-1.5 text-slate-300 truncate max-w-[100px]" title={mapping.fieldName}>
                      {mapping.fieldName || '(unnamed)'}
                      {isToken && <span className="text-amber-400 ml-1">🔐</span>}
                    </td>
                    <td className="px-2 py-1.5 text-slate-500">{input?.type || 'text'}</td>
                    <td className="px-2 py-1.5">
                      <input
                        type="text"
                        value={mapping.payload}
                        onChange={(e) => handleFieldMappingChange(mapping.fieldName, { payload: e.target.value })}
                        placeholder="Use global"
                        disabled={!mapping.enabled}
                        className="w-full bg-slate-900 border border-slate-700 rounded px-2 py-1 text-slate-300 text-[10px] disabled:opacity-50"
                      />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <button
            type="button"
            onClick={handleApplyPayloadToAll}
            className="w-full text-[10px] text-slate-400 hover:text-slate-300 py-1.5 border-t border-slate-700 bg-slate-800 transition-colors"
          >
            Apply selected payload to all enabled fields
          </button>
        </div>
      )}

      {/* Categories */}
      <div className="mb-2 flex-shrink-0">
        <div className="flex flex-wrap gap-1">
          {fuzzCategories.map((cat) => (
            <button
              key={cat.key}
              type="button"
              onClick={() => handleCategoryChange(cat.key)}
              className={`rounded px-1.5 py-0.5 text-[9px] border transition-colors ${getCategoryStyle(cat.key)}`}
            >
              <span className="mr-0.5">{cat.icon}</span>
              {cat.label}
            </button>
          ))}
        </div>
      </div>

      {/* Payload list - main scrollable area */}
      <div className="flex-1 overflow-y-auto min-h-0 mb-2">
        <div className="space-y-0.5">
          {paginatedPayloads.map((payload, idx) => (
            <button
              key={`${activeCategory}-${page}-${idx}`}
              type="button"
              onClick={() => update({ selectedPayload: payload })}
              className={`w-full rounded px-2 py-1 text-[9px] border text-left transition-colors font-mono truncate ${
                selectedPayload === payload
                  ? 'bg-blue-500/20 border-blue-500/50 text-blue-300'
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
            className={`w-full rounded px-2 py-1 text-[9px] border text-left transition-colors ${
              selectedPayload === '__custom__'
                ? 'bg-purple-500/20 border-purple-500/50 text-purple-300'
                : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
            }`}
          >
            ✏️ Custom
          </button>
        </div>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mb-2 pt-2 border-t border-slate-700 flex-shrink-0">
          <button
            type="button"
            onClick={() => setPage(Math.max(0, page - 1))}
            disabled={page === 0}
            className="text-[11px] text-slate-400 hover:text-slate-200 disabled:opacity-30"
          >
            ← Prev
          </button>
          <span className="text-[11px] text-slate-500">
            {page + 1} / {totalPages}
          </span>
          <button
            type="button"
            onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
            disabled={page >= totalPages - 1}
            className="text-[11px] text-slate-400 hover:text-slate-200 disabled:opacity-30"
          >
            Next →
          </button>
        </div>
      )}

      {/* Custom payload input */}
      {selectedPayload === '__custom__' && (
        <input
          type="text"
          value={customPayload}
          onChange={(event) => update({ customPayload: event.target.value })}
          className="w-full rounded-md bg-slate-800 text-slate-200 text-[11px] px-3 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 mb-2 font-mono flex-shrink-0"
          placeholder="Enter custom payload"
        />
      )}

      {/* Status message */}
      {data?.status && (
        <div className="text-[11px] text-slate-500 mb-2 flex-shrink-0">{data.status}</div>
      )}

      {/* Validation Errors */}
      {validationErrors.length > 0 && (
        <div className="mb-2 flex-shrink-0 rounded-lg border border-amber-500/30 bg-amber-500/10 p-2">
          <div className="text-[10px] uppercase tracking-widest text-amber-300 mb-1 font-medium">Validation Errors</div>
          <div className="space-y-1">
            {validationErrors.map((err, idx) => (
              <div key={idx} className="text-[10px] text-amber-200">
                <span className="text-amber-400">{err.field}:</span> {err.message}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Results panel */}
      {lastResult && lastResult.formFound && (
        <div className="mb-2 flex-shrink-0 border border-slate-700 rounded-lg overflow-hidden">
          <button
            type="button"
            onClick={() => setShowResults(!showResults)}
            className="w-full flex items-center justify-between px-3 py-2 bg-slate-800 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
          >
            <span>
              {lastResult.success ? '✓' : '⚠'} Results: {lastResult.appliedCount}/{lastResult.totalFields} fields
            </span>
            <span className="text-slate-500">{showResults ? '▼' : '▶'}</span>
          </button>
          {showResults && (
            <div className="max-h-32 overflow-y-auto bg-slate-900/50">
              {lastResult.fields.map((field, idx) => (
                <div
                  key={idx}
                  className={`flex items-center gap-2 px-3 py-1.5 text-[10px] border-t border-slate-800 ${
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
                    <span className="text-slate-600 truncate max-w-[100px]" title={field.reason}>
                      {field.reason.replace('Skipped: ', '')}
                    </span>
                  )}
                </div>
              ))}
              {lastResult.fields.length === 0 && (
                <div className="px-3 py-2 text-[10px] text-slate-500 text-center">
                  No fields in this form
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* DOM Mutations */}
      {domMutations.length > 0 && (
        <div className="mb-2 flex-shrink-0 border border-purple-500/30 rounded-lg overflow-hidden">
          <div className="px-3 py-1.5 bg-purple-500/10 text-[10px] text-purple-300 uppercase tracking-widest font-medium">
            DOM Mutations ({domMutations.length})
          </div>
          <div className="max-h-24 overflow-y-auto bg-slate-900/50">
            {domMutations.slice(-10).map((mutation, idx) => (
              <div key={idx} className="px-3 py-1 text-[10px] text-slate-400 border-t border-slate-800 font-mono">
                <span className="text-purple-400">{mutation.type}</span>
                <span className="text-slate-600"> on </span>
                <span className="text-slate-300">{mutation.target}</span>
                {mutation.attributeName && (
                  <span className="text-slate-500"> [{mutation.attributeName}]</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Response Panel */}
      {lastResponse && (
        <div className="mb-2 flex-shrink-0 border border-cyan-500/30 rounded-lg overflow-hidden">
          <div className="px-3 py-1.5 bg-cyan-500/10 text-[10px] uppercase tracking-widest flex items-center gap-2 font-medium">
            <span className="text-cyan-300">Response</span>
            {lastResponse.status && (
              <span className={`${lastResponse.status < 400 ? 'text-emerald-400' : 'text-rose-400'}`}>
                {lastResponse.status}
              </span>
            )}
          </div>
          {lastResponse.body && (
            <div className="max-h-24 overflow-y-auto bg-slate-900/50 p-2">
              <pre className="text-[10px] text-slate-400 font-mono whitespace-pre-wrap break-all">
                {lastResponse.body.slice(0, 500)}
                {lastResponse.body.length > 500 && '...'}
              </pre>
            </div>
          )}
          {lastResponse.error && (
            <div className="px-3 py-1.5 text-[10px] text-rose-400">
              {lastResponse.error}
            </div>
          )}
        </div>
      )}

      {/* Action Buttons */}
      <div className="flex gap-2 flex-shrink-0">
        <button
          type="button"
          onClick={handleApply}
          disabled={forms.length === 0 || (!selectedPayload || (selectedPayload === '__custom__' && !customPayload)) || isSubmitting}
          className="flex-1 rounded-md px-3 py-2 text-[11px] text-white transition-colors disabled:opacity-50 bg-blue-600 hover:bg-blue-500"
        >
          {isSubmitting ? '⏳ Submitting...' : submitMode === 'inject' ? '💉 Inject Payload' : submitMode === 'preview' ? '👁 Preview' : '📤 Inject & Submit'}
        </button>
      </div>
    </div>
  );
};
export class FormFuzzerTool {
  static Component = FormFuzzerToolComponent;
}
