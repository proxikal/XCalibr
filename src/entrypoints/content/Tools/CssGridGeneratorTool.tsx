import React, { useEffect, useRef } from 'react';
import type {
  CssGridGeneratorData
} from './tool-types';

const parseGridTemplate = (template: string): number => {
  const trimmed = template.trim();
  const repeatMatch = trimmed.match(/^repeat\s*\(\s*(\d+)/);
  if (repeatMatch) {
    return parseInt(repeatMatch[1], 10);
  }
  const parts = trimmed.split(/\s+/).filter(Boolean);
  return Math.max(1, parts.length);
};

const CssGridGeneratorToolComponent = ({
  data,
  onChange
}: {
  data: CssGridGeneratorData | undefined;
  onChange: (next: CssGridGeneratorData) => void;
}) => {
  const columns = data?.columns ?? 'repeat(3, 1fr)';
  const rows = data?.rows ?? 'auto';
  const gap = data?.gap ?? '16px';
  const output = data?.output ?? '';
  const isActive = data?.isActive ?? false;
  const drawnWidth = data?.drawnWidth;
  const drawnHeight = data?.drawnHeight;

  const overlayRef = useRef<HTMLDivElement | null>(null);
  const selectionRef = useRef<HTMLDivElement | null>(null);
  const dimensionLabelRef = useRef<HTMLDivElement | null>(null);
  const dragStartRef = useRef<{ x: number; y: number } | null>(null);

  useEffect(() => {
    // Access the real page document, not shadow DOM document
    const pageDoc = window.document;

    console.log('[CssGridGenerator] useEffect running, isActive:', isActive);

    if (!isActive) {
      if (overlayRef.current) {
        overlayRef.current.remove();
        overlayRef.current = null;
      }
      if (selectionRef.current) {
        selectionRef.current.remove();
        selectionRef.current = null;
      }
      if (dimensionLabelRef.current) {
        dimensionLabelRef.current.remove();
        dimensionLabelRef.current = null;
      }
      return;
    }

    const numCols = parseGridTemplate(columns);
    const numRows = rows === 'auto' ? 2 : parseGridTemplate(rows);

    const createOverlay = () => {
      const div = pageDoc.createElement('div');
      div.id = 'xcalibr-grid-overlay';
      div.setAttribute('style', `
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        width: 100vw !important;
        height: 100vh !important;
        z-index: 2147483647 !important;
        cursor: crosshair !important;
        background: rgba(0, 0, 0, 0.2) !important;
        pointer-events: auto !important;
      `.replace(/\n/g, ''));
      pageDoc.body.appendChild(div);
      return div;
    };

    const createSelection = () => {
      const div = pageDoc.createElement('div');
      div.id = 'xcalibr-grid-selection';
      div.setAttribute('style', `
        position: fixed !important;
        border: 2px dashed #3b82f6 !important;
        background: rgba(59, 130, 246, 0.05) !important;
        z-index: 2147483647 !important;
        pointer-events: none !important;
        display: none;
        box-sizing: border-box !important;
      `.replace(/\n/g, ''));
      pageDoc.body.appendChild(div);
      return div;
    };

    const createDimensionLabel = () => {
      const div = pageDoc.createElement('div');
      div.id = 'xcalibr-grid-dimensions';
      div.setAttribute('style', `
        position: fixed !important;
        z-index: 2147483647 !important;
        pointer-events: none !important;
        display: none;
        background: rgba(15, 23, 42, 0.95) !important;
        border: 1px solid rgba(59, 130, 246, 0.5) !important;
        border-radius: 4px !important;
        padding: 4px 8px !important;
        font-size: 11px !important;
        font-family: ui-monospace, SFMono-Regular, monospace !important;
        color: #e2e8f0 !important;
        white-space: nowrap !important;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3) !important;
      `.replace(/\n/g, ''));
      pageDoc.body.appendChild(div);
      return div;
    };

    const buildGridContent = (width: number, height: number): string => {
      if (width < 20 || height < 20) return '';

      const elements: string[] = [];

      // Column lines
      for (let i = 1; i < numCols; i++) {
        const x = Math.round((width / numCols) * i);
        elements.push(`<div style="position:absolute;left:${x}px;top:0;width:1px;height:100%;background:rgba(59,130,246,0.5);"></div>`);
      }

      // Row lines
      for (let i = 1; i < numRows; i++) {
        const y = Math.round((height / numRows) * i);
        elements.push(`<div style="position:absolute;left:0;top:${y}px;width:100%;height:1px;background:rgba(59,130,246,0.5);"></div>`);
      }

      // Grid info badge
      elements.push(`<div style="position:absolute;top:4px;left:4px;background:rgba(59,130,246,0.9);color:white;font-size:10px;font-family:ui-monospace,monospace;padding:2px 6px;border-radius:3px;">${numCols}×${numRows}</div>`);

      return elements.join('');
    };

    console.log('[CssGridGenerator] Creating overlay elements...');
    overlayRef.current = createOverlay();
    selectionRef.current = createSelection();
    dimensionLabelRef.current = createDimensionLabel();
    console.log('[CssGridGenerator] Overlay created:', overlayRef.current);

    const handleMouseDown = (event: MouseEvent) => {
      console.log('[CssGridGenerator] mousedown at', event.clientX, event.clientY);
      event.preventDefault();
      event.stopPropagation();
      dragStartRef.current = { x: event.clientX, y: event.clientY };

      if (selectionRef.current) {
        selectionRef.current.style.setProperty('display', 'block', 'important');
        selectionRef.current.style.setProperty('left', event.clientX + 'px', 'important');
        selectionRef.current.style.setProperty('top', event.clientY + 'px', 'important');
        selectionRef.current.style.setProperty('width', '0px', 'important');
        selectionRef.current.style.setProperty('height', '0px', 'important');
        selectionRef.current.innerHTML = '';
      }

      if (dimensionLabelRef.current) {
        dimensionLabelRef.current.style.setProperty('display', 'block', 'important');
        dimensionLabelRef.current.style.setProperty('left', (event.clientX + 15) + 'px', 'important');
        dimensionLabelRef.current.style.setProperty('top', (event.clientY + 15) + 'px', 'important');
        dimensionLabelRef.current.textContent = '0×0px';
      }
    };

    const handleMouseMove = (event: MouseEvent) => {
      if (!dragStartRef.current) return;

      const width = Math.abs(event.clientX - dragStartRef.current.x);
      const height = Math.abs(event.clientY - dragStartRef.current.y);
      const left = Math.min(event.clientX, dragStartRef.current.x);
      const top = Math.min(event.clientY, dragStartRef.current.y);

      if (selectionRef.current) {
        selectionRef.current.style.setProperty('left', left + 'px', 'important');
        selectionRef.current.style.setProperty('top', top + 'px', 'important');
        selectionRef.current.style.setProperty('width', width + 'px', 'important');
        selectionRef.current.style.setProperty('height', height + 'px', 'important');
        selectionRef.current.innerHTML = buildGridContent(width, height);
      }

      if (dimensionLabelRef.current) {
        dimensionLabelRef.current.style.setProperty('left', (event.clientX + 15) + 'px', 'important');
        dimensionLabelRef.current.style.setProperty('top', (event.clientY + 15) + 'px', 'important');
        dimensionLabelRef.current.innerHTML = `<span style="color:#60a5fa">${width}</span><span style="color:#64748b">×</span><span style="color:#60a5fa">${height}</span><span style="color:#64748b">px</span>`;
      }
    };

    const handleMouseUp = (event: MouseEvent) => {
      if (!dragStartRef.current) return;
      const width = Math.abs(event.clientX - dragStartRef.current.x);
      const height = Math.abs(event.clientY - dragStartRef.current.y);
      dragStartRef.current = null;

      if (width > 10 && height > 10) {
        const css = `display: grid;\ngrid-template-columns: ${columns};\ngrid-template-rows: ${rows};\ngap: ${gap};\nwidth: ${width}px;\nheight: ${height}px;`;
        onChange({
          columns,
          rows,
          gap,
          output: css,
          isActive: false,
          drawnWidth: width,
          drawnHeight: height
        });
      } else {
        onChange({ ...data, isActive: false });
      }
    };

    const overlay = overlayRef.current;
    overlay.addEventListener('mousedown', handleMouseDown);
    overlay.addEventListener('mousemove', handleMouseMove);
    overlay.addEventListener('mouseup', handleMouseUp);

    return () => {
      overlay.removeEventListener('mousedown', handleMouseDown);
      overlay.removeEventListener('mousemove', handleMouseMove);
      overlay.removeEventListener('mouseup', handleMouseUp);
      if (overlayRef.current) {
        overlayRef.current.remove();
        overlayRef.current = null;
      }
      if (selectionRef.current) {
        selectionRef.current.remove();
        selectionRef.current = null;
      }
      if (dimensionLabelRef.current) {
        dimensionLabelRef.current.remove();
        dimensionLabelRef.current = null;
      }
    };
  }, [isActive, columns, rows, gap, data, onChange]);

  const handleGenerate = () => {
    const widthPart = drawnWidth ? `\nwidth: ${drawnWidth}px;` : '';
    const heightPart = drawnHeight ? `\nheight: ${drawnHeight}px;` : '';
    const css = `display: grid;\ngrid-template-columns: ${columns};\ngrid-template-rows: ${rows};\ngap: ${gap};${widthPart}${heightPart}`;
    onChange({ columns, rows, gap, output: css, drawnWidth, drawnHeight });
  };

  const handleActivate = () => {
    console.log('[CssGridGenerator] Button clicked, toggling isActive from', isActive, 'to', !isActive);
    onChange({ ...data, isActive: !isActive });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">CSS Grid Generator</div>
      <div className="text-[11px] text-slate-500">
        Click &quot;Draw Grid&quot; then drag on the page to define dimensions.
      </div>
      <button
        type="button"
        onClick={handleActivate}
        className={`w-full rounded px-2 py-1.5 text-xs border transition-colors ${
          isActive
            ? 'bg-blue-500/10 border-blue-500/40 text-blue-200'
            : 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700'
        }`}
      >
        {isActive ? 'Drawing... (drag on page)' : 'Draw Grid on Page'}
      </button>

      {(drawnWidth || drawnHeight) && (
        <div className="text-[10px] text-slate-400">
          Drawn: {drawnWidth}px × {drawnHeight}px
        </div>
      )}

      <input
        type="text"
        value={columns}
        onChange={(event) => onChange({ ...data, columns: event.target.value })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="Columns (e.g. repeat(3, 1fr))"
      />
      <input
        type="text"
        value={rows}
        onChange={(event) => onChange({ ...data, rows: event.target.value })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="Rows (e.g. auto)"
      />
      <input
        type="text"
        value={gap}
        onChange={(event) => onChange({ ...data, gap: event.target.value })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="Gap (e.g. 16px)"
      />
      <button
        type="button"
        onClick={handleGenerate}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
      >
        Generate CSS
      </button>
      <textarea
        value={output}
        readOnly
        rows={5}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="CSS output..."
      />
      {output && (
        <button
          type="button"
          onClick={() => navigator.clipboard.writeText(output)}
          className="w-full rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Copy CSS
        </button>
      )}
    </div>
  );
};
export class CssGridGeneratorTool {
  static Component = CssGridGeneratorToolComponent;
}
