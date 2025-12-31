import React, { useState, useEffect, useRef } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faSearch, faCopy, faEyeSlash, faEdit, faCheck, faDownload, faSync, faEye } from '@fortawesome/free-solid-svg-icons';

export type HiddenType = 'input-hidden' | 'css-hidden' | 'css-invisible' | 'css-offscreen' | 'aria-hidden';

export type ValueType = 'token' | 'uuid' | 'json' | 'base64' | 'number' | 'boolean' | 'empty' | 'text';

export type HiddenField = {
  name: string;
  value: string;
  formIndex: number;
  formAction?: string;
  id?: string;
  hiddenType: HiddenType;
  valueType: ValueType;
  element?: string;
};

export type HiddenFieldRevealerData = {
  fields?: HiddenField[];
  scannedAt?: number;
  error?: string;
  watchingMutations?: boolean;
  showCssHidden?: boolean;
};

type Props = {
  data: HiddenFieldRevealerData | undefined;
  onChange: (data: HiddenFieldRevealerData) => void;
};

// Infer the type of value
const inferValueType = (value: string): ValueType => {
  if (!value || value.trim() === '') return 'empty';
  if (value === 'true' || value === 'false') return 'boolean';
  if (/^-?\d+(\.\d+)?$/.test(value)) return 'number';
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) return 'uuid';
  if (/^eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*$/.test(value)) return 'token';
  if (/^[a-zA-Z0-9_-]{20,}$/.test(value)) return 'token';
  try {
    JSON.parse(value);
    return 'json';
  } catch {}
  try {
    if (/^[A-Za-z0-9+/]+=*$/.test(value) && value.length > 10) {
      atob(value);
      return 'base64';
    }
  } catch {}
  return 'text';
};

// Check if element is visually hidden via CSS
const isElementCssHidden = (el: Element): HiddenType | null => {
  const style = window.getComputedStyle(el);
  if (style.display === 'none') return 'css-hidden';
  if (style.visibility === 'hidden') return 'css-invisible';
  if (parseFloat(style.opacity) === 0) return 'css-invisible';
  const rect = el.getBoundingClientRect();
  if (rect.width === 0 && rect.height === 0) return 'css-offscreen';
  if (rect.left < -9999 || rect.top < -9999) return 'css-offscreen';
  if (el.getAttribute('aria-hidden') === 'true') return 'aria-hidden';
  return null;
};

const HiddenFieldRevealer: React.FC<Props> = ({ data, onChange }) => {
  const fields = data?.fields ?? [];
  const scannedAt = data?.scannedAt;
  const error = data?.error;
  const showCssHidden = data?.showCssHidden ?? true;
  const watchingMutations = data?.watchingMutations ?? false;
  const [scanning, setScanning] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [editingIndex, setEditingIndex] = useState<number | null>(null);
  const [editValue, setEditValue] = useState('');
  const observerRef = useRef<MutationObserver | null>(null);
  const [mutationCount, setMutationCount] = useState(0);

  const scanPage = () => {
    setScanning(true);
    try {
      const foundFields: HiddenField[] = [];
      const seenIds = new Set<string>();
      const forms = document.querySelectorAll('form');

      // Scan type="hidden" inputs in forms
      forms.forEach((form, formIndex) => {
        const hiddenInputs = form.querySelectorAll('input[type="hidden"]');
        hiddenInputs.forEach((input) => {
          const htmlInput = input as HTMLInputElement;
          const fieldId = `${htmlInput.name}-${htmlInput.id}-${formIndex}`;
          if (seenIds.has(fieldId)) return;
          seenIds.add(fieldId);
          foundFields.push({
            name: htmlInput.name || htmlInput.id || '[unnamed]',
            value: htmlInput.value,
            formIndex,
            formAction: form.action || '[no action]',
            id: htmlInput.id || undefined,
            hiddenType: 'input-hidden',
            valueType: inferValueType(htmlInput.value),
            element: htmlInput.outerHTML.substring(0, 150)
          });
        });

        // Scan CSS-hidden inputs if enabled
        if (showCssHidden) {
          const allInputs = form.querySelectorAll('input:not([type="hidden"]), textarea, select');
          allInputs.forEach((input) => {
            const hiddenType = isElementCssHidden(input);
            if (hiddenType) {
              const htmlInput = input as HTMLInputElement;
              const fieldId = `${htmlInput.name}-${htmlInput.id}-${formIndex}-css`;
              if (seenIds.has(fieldId)) return;
              seenIds.add(fieldId);
              foundFields.push({
                name: htmlInput.name || htmlInput.id || '[unnamed]',
                value: htmlInput.value,
                formIndex,
                formAction: form.action || '[no action]',
                id: htmlInput.id || undefined,
                hiddenType,
                valueType: inferValueType(htmlInput.value),
                element: htmlInput.outerHTML.substring(0, 150)
              });
            }
          });
        }
      });

      // Standalone hidden inputs
      const standaloneHidden = document.querySelectorAll('input[type="hidden"]:not(form input)');
      standaloneHidden.forEach((input) => {
        const htmlInput = input as HTMLInputElement;
        const fieldId = `${htmlInput.name}-${htmlInput.id}-standalone`;
        if (seenIds.has(fieldId)) return;
        seenIds.add(fieldId);
        foundFields.push({
          name: htmlInput.name || htmlInput.id || '[unnamed]',
          value: htmlInput.value,
          formIndex: -1,
          formAction: '[standalone]',
          id: htmlInput.id || undefined,
          hiddenType: 'input-hidden',
          valueType: inferValueType(htmlInput.value),
          element: htmlInput.outerHTML.substring(0, 150)
        });
      });

      // Scan all CSS-hidden inputs outside forms if enabled
      if (showCssHidden) {
        const allInputs = document.querySelectorAll('input:not([type="hidden"]):not(form input), textarea:not(form textarea), select:not(form select)');
        allInputs.forEach((input) => {
          const hiddenType = isElementCssHidden(input);
          if (hiddenType) {
            const htmlInput = input as HTMLInputElement;
            const fieldId = `${htmlInput.name}-${htmlInput.id}-standalone-css`;
            if (seenIds.has(fieldId)) return;
            seenIds.add(fieldId);
            foundFields.push({
              name: htmlInput.name || htmlInput.id || '[unnamed]',
              value: htmlInput.value,
              formIndex: -1,
              formAction: '[standalone]',
              id: htmlInput.id || undefined,
              hiddenType,
              valueType: inferValueType(htmlInput.value),
              element: htmlInput.outerHTML.substring(0, 150)
            });
          }
        });
      }

      onChange({
        ...data,
        fields: foundFields,
        scannedAt: Date.now(),
        error: undefined
      });
    } catch (e) {
      onChange({
        ...data,
        error: e instanceof Error ? e.message : 'Scan failed',
        scannedAt: Date.now()
      });
    } finally {
      setScanning(false);
    }
  };

  // MutationObserver to watch for dynamic field changes
  const toggleMutationWatch = () => {
    if (watchingMutations) {
      observerRef.current?.disconnect();
      observerRef.current = null;
      onChange({ ...data, watchingMutations: false });
    } else {
      observerRef.current = new MutationObserver((mutations) => {
        let hasRelevantChange = false;
        for (const mutation of mutations) {
          if (mutation.type === 'childList' || mutation.type === 'attributes') {
            const target = mutation.target as Element;
            if (target.tagName === 'INPUT' || target.tagName === 'FORM' || target.querySelector?.('input')) {
              hasRelevantChange = true;
              break;
            }
          }
        }
        if (hasRelevantChange) {
          setMutationCount(c => c + 1);
        }
      });
      observerRef.current.observe(document.body, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['value', 'type', 'style', 'class', 'hidden']
      });
      onChange({ ...data, watchingMutations: true });
    }
  };

  // Cleanup observer on unmount
  useEffect(() => {
    return () => {
      observerRef.current?.disconnect();
    };
  }, []);

  const copyToClipboard = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 1500);
  };

  const startEdit = (index: number, currentValue: string) => {
    setEditingIndex(index);
    setEditValue(currentValue);
  };

  const saveEdit = (field: HiddenField, index: number) => {
    // Update the actual DOM element
    const selector = field.id
      ? `input#${CSS.escape(field.id)}`
      : `input[name="${CSS.escape(field.name)}"][type="hidden"]`;

    const inputs = document.querySelectorAll(selector);
    inputs.forEach((input) => {
      (input as HTMLInputElement).value = editValue;
    });

    // Update state
    const updatedFields = [...fields];
    updatedFields[index] = { ...field, value: editValue };
    onChange({ ...data, fields: updatedFields });

    setEditingIndex(null);
    setEditValue('');
  };

  const copyAllAsJson = () => {
    const json = JSON.stringify(fields, null, 2);
    navigator.clipboard.writeText(json);
    setCopiedIndex(-1);
    setTimeout(() => setCopiedIndex(null), 1500);
  };

  const exportAsJson = () => {
    const exportData = {
      url: window.location.href,
      scannedAt: scannedAt ? new Date(scannedAt).toISOString() : null,
      fields: fields.map(f => ({
        ...f,
        element: undefined // Remove raw HTML for cleaner export
      }))
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `hidden-fields-${window.location.hostname}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getHiddenTypeBadge = (type: HiddenType) => {
    const badges: Record<HiddenType, { label: string; color: string }> = {
      'input-hidden': { label: 'hidden', color: 'bg-purple-900/50 text-purple-300' },
      'css-hidden': { label: 'display:none', color: 'bg-yellow-900/50 text-yellow-300' },
      'css-invisible': { label: 'invisible', color: 'bg-orange-900/50 text-orange-300' },
      'css-offscreen': { label: 'offscreen', color: 'bg-blue-900/50 text-blue-300' },
      'aria-hidden': { label: 'aria-hidden', color: 'bg-pink-900/50 text-pink-300' }
    };
    return badges[type];
  };

  const getValueTypeBadge = (type: ValueType) => {
    const badges: Record<ValueType, { label: string; color: string }> = {
      'token': { label: 'TOKEN', color: 'bg-red-900/50 text-red-300' },
      'uuid': { label: 'UUID', color: 'bg-cyan-900/50 text-cyan-300' },
      'json': { label: 'JSON', color: 'bg-green-900/50 text-green-300' },
      'base64': { label: 'B64', color: 'bg-amber-900/50 text-amber-300' },
      'number': { label: 'NUM', color: 'bg-slate-700 text-slate-300' },
      'boolean': { label: 'BOOL', color: 'bg-slate-700 text-slate-300' },
      'empty': { label: 'EMPTY', color: 'bg-slate-800 text-slate-500' },
      'text': { label: 'TEXT', color: 'bg-slate-700 text-slate-400' }
    };
    return badges[type];
  };

  const inputHiddenCount = fields.filter(f => f.hiddenType === 'input-hidden').length;
  const cssHiddenCount = fields.filter(f => f.hiddenType !== 'input-hidden').length;

  // Group fields by form
  const groupedFields = fields.reduce((acc, field) => {
    const key = field.formIndex === -1 ? 'Standalone' : `Form ${field.formIndex + 1}`;
    if (!acc[key]) {
      acc[key] = { action: field.formAction, fields: [] };
    }
    acc[key].fields.push(field);
    return acc;
  }, {} as Record<string, { action?: string; fields: HiddenField[] }>);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">Hidden Field Revealer</div>
        <div className="flex gap-1">
          {fields.length > 0 && (
            <>
              <button
                onClick={exportAsJson}
                className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
                title="Export as JSON"
              >
                <FontAwesomeIcon icon={faDownload} className="w-2.5 h-2.5" />
              </button>
              <button
                onClick={copyAllAsJson}
                className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
                title="Copy as JSON"
              >
                <FontAwesomeIcon icon={faCopy} className="w-2.5 h-2.5" />
                {copiedIndex === -1 && <span className="text-green-400 ml-1">!</span>}
              </button>
            </>
          )}
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Finds hidden fields including CSS-hidden elements. Detects value types and watches for dynamic changes.
      </div>

      <div className="flex gap-2 mb-3">
        <button
          onClick={scanPage}
          disabled={scanning}
          className="flex-1 rounded bg-purple-600/20 border border-purple-500/30 px-2 py-1.5 text-[11px] text-purple-300 hover:bg-purple-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
        >
          <FontAwesomeIcon icon={faSearch} className="w-3 h-3" />
          {scanning ? 'Scanning...' : 'Scan'}
        </button>
        <button
          onClick={toggleMutationWatch}
          className={`rounded px-2 py-1.5 text-[11px] transition-colors flex items-center gap-1 ${
            watchingMutations
              ? 'bg-green-600/30 border border-green-500/50 text-green-300'
              : 'bg-slate-800 border border-slate-700 text-slate-400 hover:border-slate-500'
          }`}
          title="Watch for dynamic changes"
        >
          <FontAwesomeIcon icon={faSync} className={`w-2.5 h-2.5 ${watchingMutations ? 'animate-spin' : ''}`} />
          {mutationCount > 0 && <span className="text-yellow-400">({mutationCount})</span>}
        </button>
      </div>

      {/* Options */}
      <div className="flex items-center gap-3 mb-3 text-[10px]">
        <label className="flex items-center gap-1.5 text-slate-400 cursor-pointer">
          <input
            type="checkbox"
            checked={showCssHidden}
            onChange={(e) => onChange({ ...data, showCssHidden: e.target.checked })}
            className="rounded bg-slate-700 border-slate-600 w-3 h-3"
          />
          <FontAwesomeIcon icon={faEye} className="w-2.5 h-2.5" />
          CSS Hidden
        </label>
        {scannedAt && (
          <div className="text-slate-500 ml-auto">
            <span className="text-purple-400">{inputHiddenCount}</span> input +{' '}
            <span className="text-yellow-400">{cssHiddenCount}</span> css
          </div>
        )}
      </div>

      {error && (
        <div className="text-red-400 text-[10px] bg-red-900/20 border border-red-500/30 p-2 rounded mb-3">
          {error}
        </div>
      )}

      {scannedAt && (
        <div className="text-[10px] text-slate-500 mb-2">
          Last scanned: {new Date(scannedAt).toLocaleTimeString()}
        </div>
      )}

      {fields.length > 0 && (
        <div className="flex items-center gap-2 text-purple-400 text-[11px] font-medium mb-2">
          <FontAwesomeIcon icon={faEyeSlash} className="w-3 h-3" />
          Hidden Fields Found ({fields.length})
        </div>
      )}

      <div className="flex-1 overflow-y-auto space-y-3 min-h-0">
        {Object.entries(groupedFields).map(([groupName, group]) => (
          <div key={groupName} className="space-y-2">
            <div className="text-[10px] text-slate-500 border-b border-slate-700 pb-1">
              <span className="font-medium text-slate-300">{groupName}</span>
              {group.action && group.action !== '[standalone]' && (
                <span className="ml-2 text-slate-600 truncate">Action: {group.action}</span>
              )}
            </div>
            <div className="space-y-2">
              {group.fields.map((field, idx) => {
                const globalIdx = fields.indexOf(field);
                const hiddenBadge = getHiddenTypeBadge(field.hiddenType);
                const valueBadge = getValueTypeBadge(field.valueType);
                return (
                  <div key={idx} className={`rounded border p-2 ${
                    field.hiddenType === 'input-hidden'
                      ? 'border-slate-700 bg-slate-800/50'
                      : 'border-yellow-700/50 bg-yellow-900/10'
                  }`}>
                    <div className="flex justify-between items-start">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-purple-400 text-[11px] font-medium">
                            {field.name}
                          </span>
                          {field.id && <span className="text-slate-500 text-[10px]">#{field.id}</span>}
                          <span className={`text-[8px] px-1.5 py-0.5 rounded ${hiddenBadge.color}`}>
                            {hiddenBadge.label}
                          </span>
                          <span className={`text-[8px] px-1.5 py-0.5 rounded ${valueBadge.color}`}>
                            {valueBadge.label}
                          </span>
                        </div>
                        {editingIndex === globalIdx ? (
                          <div className="flex gap-2 mt-1">
                            <input
                              type="text"
                              value={editValue}
                              onChange={(e) => setEditValue(e.target.value)}
                              className="flex-1 rounded bg-slate-700 text-slate-200 text-[10px] px-2 py-0.5 border border-slate-600 focus:outline-none font-mono"
                              autoFocus
                            />
                            <button
                              onClick={() => saveEdit(field, globalIdx)}
                              className="rounded bg-green-600/20 border border-green-500/30 px-2 py-0.5 text-[10px] text-green-300 hover:bg-green-600/30 transition-colors"
                            >
                              <FontAwesomeIcon icon={faCheck} className="w-2.5 h-2.5" />
                            </button>
                          </div>
                        ) : (
                          <div className="text-slate-300 text-[10px] font-mono mt-1 break-all">
                            {field.value || <span className="text-slate-600 italic">[empty]</span>}
                          </div>
                        )}
                      </div>
                      <div className="flex gap-1 ml-2 flex-shrink-0">
                        <button
                          onClick={() => startEdit(globalIdx, field.value)}
                          className="text-[9px] text-slate-500 hover:text-yellow-400"
                          title="Edit"
                        >
                          <FontAwesomeIcon icon={faEdit} className="w-2.5 h-2.5" />
                        </button>
                        <button
                          onClick={() => copyToClipboard(`${field.name}=${field.value}`, globalIdx)}
                          className="text-[9px] text-slate-500 hover:text-slate-300"
                          title="Copy"
                        >
                          <FontAwesomeIcon icon={faCopy} className="w-2.5 h-2.5" />
                        </button>
                      </div>
                    </div>
                    {copiedIndex === globalIdx && (
                      <span className="text-green-400 text-[9px]">Copied!</span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        ))}

        {scannedAt && fields.length === 0 && (
          <div className="text-[11px] text-green-400 text-center py-4">
            No hidden fields found on this page.
          </div>
        )}
      </div>

      <div className="text-[10px] text-slate-500 border-t border-slate-700 pt-2 mt-3">
        <div><strong>Common hidden fields:</strong></div>
        <div className="text-slate-600">CSRF tokens, user IDs, form identifiers, state variables</div>
      </div>
    </div>
  );
};

export class HiddenFieldRevealerTool {
  static Component = HiddenFieldRevealer;
}
