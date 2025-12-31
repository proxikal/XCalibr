import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faSearch, faCopy, faEyeSlash, faEdit, faCheck } from '@fortawesome/free-solid-svg-icons';

export type HiddenField = {
  name: string;
  value: string;
  formIndex: number;
  formAction?: string;
  id?: string;
};

export type HiddenFieldRevealerData = {
  fields?: HiddenField[];
  scannedAt?: number;
  error?: string;
};

type Props = {
  data: HiddenFieldRevealerData | undefined;
  onChange: (data: HiddenFieldRevealerData) => void;
};

const HiddenFieldRevealer: React.FC<Props> = ({ data, onChange }) => {
  const fields = data?.fields ?? [];
  const scannedAt = data?.scannedAt;
  const error = data?.error;
  const [scanning, setScanning] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [editingIndex, setEditingIndex] = useState<number | null>(null);
  const [editValue, setEditValue] = useState('');

  const scanPage = () => {
    setScanning(true);
    try {
      const foundFields: HiddenField[] = [];
      const forms = document.querySelectorAll('form');

      forms.forEach((form, formIndex) => {
        const hiddenInputs = form.querySelectorAll('input[type="hidden"]');
        hiddenInputs.forEach((input) => {
          const htmlInput = input as HTMLInputElement;
          foundFields.push({
            name: htmlInput.name || htmlInput.id || '[unnamed]',
            value: htmlInput.value,
            formIndex,
            formAction: form.action || '[no action]',
            id: htmlInput.id || undefined
          });
        });
      });

      // Also check for hidden inputs outside forms
      const standaloneHidden = document.querySelectorAll('input[type="hidden"]:not(form input)');
      standaloneHidden.forEach((input, idx) => {
        const htmlInput = input as HTMLInputElement;
        foundFields.push({
          name: htmlInput.name || htmlInput.id || '[unnamed]',
          value: htmlInput.value,
          formIndex: -1,
          formAction: '[standalone]',
          id: htmlInput.id || undefined
        });
      });

      onChange({
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
        <div className="flex gap-2">
          {fields.length > 0 && (
            <button
              onClick={copyAllAsJson}
              className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors flex items-center gap-1"
            >
              <FontAwesomeIcon icon={faCopy} className="w-2.5 h-2.5" />
              Copy JSON
              {copiedIndex === -1 && <span className="text-green-400 ml-1">Done!</span>}
            </button>
          )}
          <button
            onClick={scanPage}
            disabled={scanning}
            className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors flex items-center gap-1 disabled:opacity-50"
          >
            <FontAwesomeIcon icon={faSearch} className="w-3 h-3" />
            {scanning ? 'Scanning...' : 'Scan'}
          </button>
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Finds and displays all hidden form fields on the page. You can view and modify their values.
      </div>

      <button
        onClick={scanPage}
        disabled={scanning}
        className="w-full rounded bg-purple-600/20 border border-purple-500/30 px-2 py-1.5 text-[11px] text-purple-300 hover:bg-purple-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2 mb-3"
      >
        <FontAwesomeIcon icon={faSearch} className="w-3 h-3" />
        {scanning ? 'Scanning...' : 'Scan Hidden Fields'}
      </button>

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
                return (
                  <div key={idx} className="rounded border border-slate-700 bg-slate-800/50 p-2">
                    <div className="flex justify-between items-start">
                      <div className="flex-1 min-w-0">
                        <div className="text-purple-400 text-[11px] font-medium">
                          {field.name}
                          {field.id && <span className="text-slate-500 ml-2">#{field.id}</span>}
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
