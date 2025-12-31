import React from 'react';
import type { ScraperDraft, ScraperField } from '../../../shared/scraper';

type ScraperBuilderProps = {
  draft: ScraperDraft;
  showHelp: boolean;
  regexPreviewMap: Map<string, { count: number; error: string | null; capped: boolean }>;
  onUpdateDraft: (next: Partial<ScraperDraft>) => Promise<void>;
  onUpdateField: (fieldId: string, next: Partial<ScraperField>) => Promise<void>;
  onRemoveField: (fieldId: string) => Promise<void>;
  onSave: () => Promise<void>;
  onClose: () => Promise<void>;
  onShowHelp: () => void;
  onHideHelp: () => void;
};

export const ScraperBuilder: React.FC<ScraperBuilderProps> = ({
  draft,
  showHelp,
  regexPreviewMap,
  onUpdateDraft,
  onUpdateField,
  onRemoveField,
  onSave,
  onClose,
  onShowHelp,
  onHideHelp
}) => {
  return (
    <div
      className="fixed inset-0 z-[95] flex items-start justify-center bg-slate-950/70 backdrop-blur-sm"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      <div
        className="mt-12 w-full max-w-2xl max-h-[85vh] rounded-2xl border border-slate-700/80 bg-gradient-to-b from-slate-900 via-slate-900 to-slate-950 shadow-[0_24px_60px_rgba(0,0,0,0.55)] flex flex-col"
        onMouseDown={(event) => event.stopPropagation()}
      >
        {showHelp ? (
          <ScraperHelpOverlay onClose={onHideHelp} />
        ) : null}
        <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
          <div>
            <div className="text-xs text-slate-200">Build Scraper</div>
            <div className="text-[11px] text-slate-500">
              Click elements on the page to capture selectors.
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={onShowHelp}
              className="text-[11px] text-blue-300 hover:text-blue-200 transition-colors"
            >
              Explain Scraper
            </button>
            <button
              type="button"
              onClick={onClose}
              className="text-slate-400 hover:text-slate-200 transition-colors"
            >
              ×
            </button>
          </div>
        </div>
        <div className="space-y-4 px-5 py-4">
          <div className="space-y-2">
            <div className="text-[11px] uppercase tracking-[0.2em] text-slate-500">
              Scraper Name
            </div>
            <input
              type="text"
              value={draft.name}
              onChange={(event) => onUpdateDraft({ name: event.target.value })}
              className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
              placeholder="e.g. Pricing Table"
            />
          </div>
        </div>
        <div className="flex-1 overflow-y-auto px-5 pb-4 space-y-4">
          <div className="flex items-center justify-between">
            <div className="text-[11px] text-slate-500">Picker idle</div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => {
                  const nextField: ScraperField = {
                    id: `field_${Date.now()}_${Math.random().toString(16).slice(2)}`,
                    name: `Regex ${draft.fields.length + 1}`,
                    selector: 'document',
                    xpath: 'document',
                    mode: 'list',
                    source: 'regex',
                    regex: '',
                    regexFlags: 'gi'
                  };
                  onUpdateDraft({ fields: [...draft.fields, nextField] });
                }}
                className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
              >
                Add Regex Field
              </button>
              <button
                type="button"
                onClick={() => onUpdateDraft({ isPicking: true })}
                className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
              >
                Pick Elements
              </button>
            </div>
          </div>

          <div className="space-y-3">
            {draft.fields.length === 0 ? (
              <div className="text-[11px] text-slate-500">
                No fields yet. Click "Pick Elements" and select elements on the page.
              </div>
            ) : (
              draft.fields.map((field) => (
                <ScraperFieldEditor
                  key={field.id}
                  field={field}
                  regexPreview={regexPreviewMap.get(field.id)}
                  onUpdate={(next) => onUpdateField(field.id, next)}
                  onRemove={() => onRemoveField(field.id)}
                />
              ))
            )}
          </div>
        </div>
        <div className="flex items-center justify-end gap-2 border-t border-slate-800 px-5 py-4">
          <button
            type="button"
            onClick={onClose}
            className="rounded bg-slate-800 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-700 transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onSave}
            disabled={!draft.name.trim() || draft.fields.length === 0}
            className="rounded bg-blue-600 px-3 py-1.5 text-xs text-white hover:bg-blue-500 transition-colors disabled:opacity-50"
          >
            Save Scraper
          </button>
        </div>
      </div>
    </div>
  );
};

type ScraperHelpOverlayProps = {
  onClose: () => void;
};

const ScraperHelpOverlay: React.FC<ScraperHelpOverlayProps> = ({ onClose }) => {
  const steps = [
    { title: '1. Name Your Scraper', desc: 'Give the scraper a clear name so you can find it later in the Scraper List.' },
    { title: '2. Pick Elements', desc: 'Click "Pick Elements" and hover the page. Click any element you want to extract. Each click adds a field.' },
    { title: '3. Rename Fields', desc: 'Rename fields so the output makes sense (e.g. Price, Title, Description).' },
    { title: '4. Choose Mode', desc: 'Use "Single" for one value, or "List" when you want all matching elements on the page.' },
    { title: '4b. Get Every Instance', desc: 'Use List mode with a broad selector or Regex to capture all matches like emails or URLs.' },
    { title: '5. Choose Source', desc: 'Pick Text, HTML, or Attribute. Attribute is useful for links (href) or images (src).' },
    { title: '5b. Regex Source', desc: 'Add a Regex field to scan the entire page text. Start with presets like Emails or URLs and tweak the pattern if needed.' },
    { title: '6. Save Scraper', desc: 'Save when you have at least one field. It will appear in the Scraper List menu.' },
    { title: '7. Run Scraper', desc: 'Open Scraper List, choose your scraper, and review results. Use Copy JSON or Copy CSV to export.' }
  ];

  return (
    <div className="absolute inset-0 z-[96] rounded-2xl bg-slate-950/90 backdrop-blur-sm">
      <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
        <div>
          <div className="text-xs text-slate-200">Scraper Guide</div>
          <div className="text-[11px] text-slate-500">
            Learn how to build and run a scraper safely.
          </div>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="text-slate-400 hover:text-slate-200 transition-colors"
        >
          ×
        </button>
      </div>
      <div className="max-h-[70vh] overflow-y-auto px-5 py-4 space-y-4 text-[11px] text-slate-300">
        {steps.map((step) => (
          <div key={step.title}>
            <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
              {step.title}
            </div>
            <div>{step.desc}</div>
          </div>
        ))}
      </div>
    </div>
  );
};

type ScraperFieldEditorProps = {
  field: ScraperField;
  regexPreview?: { count: number; error: string | null; capped: boolean };
  onUpdate: (next: Partial<ScraperField>) => void;
  onRemove: () => void;
};

const ScraperFieldEditor: React.FC<ScraperFieldEditorProps> = ({
  field,
  regexPreview,
  onUpdate,
  onRemove
}) => {
  return (
    <div className="rounded border border-slate-800 bg-slate-900/60 p-3 space-y-2">
      <div className="flex items-center justify-between gap-2">
        <input
          type="text"
          value={field.name}
          onChange={(event) => onUpdate({ name: event.target.value })}
          className="flex-1 rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        />
        <button
          type="button"
          onClick={onRemove}
          className="text-slate-500 hover:text-rose-300 transition-colors"
        >
          ×
        </button>
      </div>

      <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
        Selector
      </div>
      <div className="text-[11px] text-slate-300 break-words">
        {field.selector}
      </div>
      <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
        XPath
      </div>
      <div className="text-[11px] text-slate-400 break-words">
        {field.xpath}
      </div>

      <div className="flex gap-2">
        {(['single', 'list'] as const).map((mode) => (
          <button
            key={mode}
            type="button"
            onClick={() => onUpdate({ mode })}
            className={`flex-1 rounded px-2 py-1 text-[11px] border transition-colors ${
              field.mode === mode
                ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
            }`}
          >
            {mode === 'single' ? 'Single' : 'List'}
          </button>
        ))}
      </div>

      <div className="flex gap-2">
        {(['text', 'html', 'attr', 'regex'] as const).map((source) => (
          <button
            key={source}
            type="button"
            onClick={() =>
              onUpdate({
                source,
                ...(source === 'regex'
                  ? { selector: 'document', xpath: 'document', mode: 'list' }
                  : {})
              })
            }
            className={`flex-1 rounded px-2 py-1 text-[11px] border transition-colors ${
              field.source === source
                ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
            }`}
          >
            {source === 'attr'
              ? 'Attribute'
              : source === 'regex'
                ? 'Regex'
                : source.toUpperCase()}
          </button>
        ))}
      </div>

      {field.source === 'attr' ? (
        <input
          type="text"
          value={field.attrName ?? ''}
          onChange={(event) => onUpdate({ attrName: event.target.value })}
          className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
          placeholder="Attribute name (e.g. href)"
        />
      ) : null}

      {field.source === 'regex' ? (
        <div className="space-y-2">
          <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
            Regex Pattern
          </div>
          <input
            type="text"
            value={field.regex ?? ''}
            onChange={(event) => onUpdate({ regex: event.target.value })}
            className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
            placeholder="e.g. [A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}"
          />
          <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
            Flags
          </div>
          <input
            type="text"
            value={field.regexFlags ?? 'gi'}
            onChange={(event) => onUpdate({ regexFlags: event.target.value })}
            className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
            placeholder="e.g. gi"
          />
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() =>
                onUpdate({
                  regex: '[A-Z0-9._%+-]+@[A-Z0-9.-]+\\\\.[A-Z]{2,}',
                  regexFlags: 'gi',
                  mode: 'list'
                })
              }
              className="flex-1 rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
            >
              Emails
            </button>
            <button
              type="button"
              onClick={() =>
                onUpdate({
                  regex: "https?://[^\\s\"'`<>]+",
                  regexFlags: 'gi',
                  mode: 'list'
                })
              }
              className="flex-1 rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
            >
              URLs
            </button>
          </div>
          {regexPreview?.error ? (
            <div className="text-[11px] text-rose-300">
              {regexPreview.error}
            </div>
          ) : (
            <div className="text-[11px] text-slate-500">
              Matches on page: {regexPreview?.count ?? 0}
              {regexPreview?.capped ? '+' : ''}
            </div>
          )}
          <div className="text-[11px] text-slate-500">
            Regex runs against full page text.
          </div>
        </div>
      ) : null}
    </div>
  );
};
