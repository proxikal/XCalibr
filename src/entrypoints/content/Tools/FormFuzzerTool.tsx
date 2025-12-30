import React, { useState } from 'react';
import {
  defaultPayloads
} from './helpers';
import type {
  FormFuzzerData
} from './tool-types';

const FormFuzzerToolComponent = ({
  data,
  onChange,
  onRefresh,
  onApply
}: {
  data: FormFuzzerData | undefined;
  onChange: (next: FormFuzzerData) => void;
  onRefresh: () => Promise<void>;
  onApply: (formIndex: number, payload: string) => Promise<boolean>;
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const payloads = data?.payloads ?? defaultPayloads;
  const selectedPayload = data?.selectedPayload ?? payloads[0] ?? '';
  const selectedFormIndex = data?.selectedFormIndex ?? 0;
  const forms = data?.forms ?? [];
  const customPayload = data?.customPayload ?? '';
  const update = (next: Partial<FormFuzzerData>) =>
    onChange({
      payloads,
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
      update({ status: 'Choose a payload to apply.' });
      return;
    }
    const ok = await onApply(selectedFormIndex, payload);
    update({
      status: ok ? 'Payload applied.' : 'Could not apply payload.'
    });
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-slate-200">Form Fuzzer</div>
        <button
          type="button"
          onClick={handleRefresh}
          disabled={isLoading}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors disabled:opacity-50"
        >
          {isLoading ? 'Scanning...' : 'Refresh Forms'}
        </button>
      </div>

      {forms.length === 0 ? (
        <div className="text-[11px] text-slate-500">
          No forms detected on this page.
        </div>
      ) : (
        <div className="space-y-2">
          <div className="text-[11px] uppercase tracking-[0.2em] text-slate-500">
            Select Form
          </div>
          <div className="space-y-1">
            {forms.map((form) => (
              <button
                key={form.index}
                type="button"
                onClick={() => update({ selectedFormIndex: form.index })}
                className={`w-full rounded px-2 py-1 text-[11px] border text-left transition-colors ${
                  selectedFormIndex === form.index
                    ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                    : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                }`}
              >
                {form.method} • {form.action}
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="space-y-2">
        <div className="text-[11px] uppercase tracking-[0.2em] text-slate-500">
          Payload
        </div>
        <div className="space-y-1">
          {payloads.map((payload) => (
            <button
              key={payload}
              type="button"
              onClick={() => update({ selectedPayload: payload })}
              className={`w-full rounded px-2 py-1 text-[11px] border text-left transition-colors ${
                selectedPayload === payload
                  ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
              }`}
            >
              {payload}
            </button>
          ))}
          <button
            type="button"
            onClick={() => update({ selectedPayload: '__custom__' })}
            className={`w-full rounded px-2 py-1 text-[11px] border text-left transition-colors ${
              selectedPayload === '__custom__'
                ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
            }`}
          >
            Custom Payload
          </button>
        </div>
        {selectedPayload === '__custom__' ? (
          <input
            type="text"
            value={customPayload}
            onChange={(event) => update({ customPayload: event.target.value })}
            className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
            placeholder="Enter custom payload"
          />
        ) : null}
      </div>

      {data?.status ? (
        <div className="text-[11px] text-slate-500">{data.status}</div>
      ) : null}

      <button
        type="button"
        onClick={handleApply}
        disabled={forms.length === 0}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Apply Payload
      </button>
    </div>
  );
};
export class FormFuzzerTool {
  static Component = FormFuzzerToolComponent;
}
