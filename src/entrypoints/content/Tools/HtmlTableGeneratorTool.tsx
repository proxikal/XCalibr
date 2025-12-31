import React from 'react';

export type HtmlTableGeneratorData = {
  rows?: number;
  columns?: number;
  includeHeader?: boolean;
  includeBorder?: boolean;
  headerLabels?: string[];
  cellContent?: string;
};

type Props = {
  data: HtmlTableGeneratorData;
  onChange: (data: HtmlTableGeneratorData) => void;
};

const HtmlTableGenerator: React.FC<Props> = ({ data, onChange }) => {
  const rows = data.rows ?? 3;
  const columns = data.columns ?? 3;
  const includeHeader = data.includeHeader ?? true;
  const includeBorder = data.includeBorder ?? true;
  const cellContent = data.cellContent ?? 'Cell';

  const generateTableHTML = () => {
    const lines: string[] = [];

    if (includeBorder) {
      lines.push('<table border="1" cellpadding="5" cellspacing="0">');
    } else {
      lines.push('<table>');
    }

    if (includeHeader) {
      lines.push('  <thead>');
      lines.push('    <tr>');
      for (let c = 1; c <= columns; c++) {
        lines.push(`      <th>Header ${c}</th>`);
      }
      lines.push('    </tr>');
      lines.push('  </thead>');
    }

    lines.push('  <tbody>');
    for (let r = 1; r <= rows; r++) {
      lines.push('    <tr>');
      for (let c = 1; c <= columns; c++) {
        lines.push(`      <td>${cellContent} ${r}-${c}</td>`);
      }
      lines.push('    </tr>');
    }
    lines.push('  </tbody>');
    lines.push('</table>');

    return lines.join('\n');
  };

  const tableHTML = generateTableHTML();

  const copyToClipboard = () => {
    navigator.clipboard.writeText(tableHTML);
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Rows</label>
          <input
            type="number"
            min="1"
            max="20"
            value={rows}
            onChange={(e) => onChange({ ...data, rows: Math.max(1, Number(e.target.value)) })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white"
          />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Columns</label>
          <input
            type="number"
            min="1"
            max="10"
            value={columns}
            onChange={(e) => onChange({ ...data, columns: Math.max(1, Number(e.target.value)) })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white"
          />
        </div>
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Cell Content Prefix</label>
        <input
          type="text"
          value={cellContent}
          onChange={(e) => onChange({ ...data, cellContent: e.target.value })}
          placeholder="Cell"
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white"
        />
      </div>

      <div className="flex gap-4">
        <label className="flex items-center gap-2 text-sm text-gray-300">
          <input
            type="checkbox"
            checked={includeHeader}
            onChange={(e) => onChange({ ...data, includeHeader: e.target.checked })}
            className="rounded border-gray-600"
          />
          Include Header
        </label>
        <label className="flex items-center gap-2 text-sm text-gray-300">
          <input
            type="checkbox"
            checked={includeBorder}
            onChange={(e) => onChange({ ...data, includeBorder: e.target.checked })}
            className="rounded border-gray-600"
          />
          Include Border
        </label>
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Preview</label>
        <div
          className="p-4 bg-white rounded overflow-auto max-h-40"
          dangerouslySetInnerHTML={{ __html: tableHTML }}
        />
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">HTML Output</label>
        <textarea
          readOnly
          value={tableHTML}
          className="w-full h-32 px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-green-400 font-mono text-xs resize-none"
        />
      </div>

      <button
        onClick={copyToClipboard}
        className="w-full py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded text-sm"
      >
        Copy HTML
      </button>
    </div>
  );
};

export class HtmlTableGeneratorTool {
  static Component = HtmlTableGenerator;
}
