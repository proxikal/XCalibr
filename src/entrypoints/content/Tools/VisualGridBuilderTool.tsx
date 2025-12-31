import React from 'react';

export type GridCell = {
  id: string;
  row: number;
  col: number;
  rowSpan: number;
  colSpan: number;
  name: string;
};

export type VisualGridBuilderData = {
  rows?: number;
  cols?: number;
  gap?: number;
  cells?: GridCell[];
  selectedCell?: string;
};

type Props = {
  data: VisualGridBuilderData | undefined;
  onChange: (data: VisualGridBuilderData) => void;
};

const generateId = () => Math.random().toString(36).substr(2, 6);

const COLORS = [
  'bg-blue-500/30', 'bg-green-500/30', 'bg-purple-500/30',
  'bg-yellow-500/30', 'bg-pink-500/30', 'bg-cyan-500/30',
  'bg-orange-500/30', 'bg-red-500/30', 'bg-indigo-500/30'
];

const VisualGridBuilder: React.FC<Props> = ({ data, onChange }) => {
  const rows = data?.rows ?? 3;
  const cols = data?.cols ?? 3;
  const gap = data?.gap ?? 8;
  const cells = data?.cells ?? [];
  const selectedCell = data?.selectedCell;

  const handleAddCell = () => {
    const newCell: GridCell = {
      id: generateId(),
      row: 1,
      col: 1,
      rowSpan: 1,
      colSpan: 1,
      name: `Area ${cells.length + 1}`
    };
    onChange({ ...data, cells: [...cells, newCell], selectedCell: newCell.id });
  };

  const handleRemoveCell = (id: string) => {
    onChange({
      ...data,
      cells: cells.filter(c => c.id !== id),
      selectedCell: selectedCell === id ? undefined : selectedCell
    });
  };

  const handleCellChange = (id: string, updates: Partial<GridCell>) => {
    onChange({
      ...data,
      cells: cells.map(c => c.id === id ? { ...c, ...updates } : c)
    });
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(generateCSS());
  };

  const generateCSS = () => {
    const lines = [
      '.container {',
      '  display: grid;',
      `  grid-template-rows: repeat(${rows}, 1fr);`,
      `  grid-template-columns: repeat(${cols}, 1fr);`,
      `  gap: ${gap}px;`
    ];

    if (cells.length > 0) {
      const areas: string[][] = Array(rows).fill(null).map(() => Array(cols).fill('.'));

      cells.forEach((cell, idx) => {
        const areaName = cell.name.replace(/\s+/g, '-').toLowerCase() || `area-${idx + 1}`;
        for (let r = cell.row - 1; r < cell.row - 1 + cell.rowSpan && r < rows; r++) {
          for (let c = cell.col - 1; c < cell.col - 1 + cell.colSpan && c < cols; c++) {
            areas[r][c] = areaName;
          }
        }
      });

      lines.push(`  grid-template-areas:`);
      areas.forEach(row => {
        lines.push(`    "${row.join(' ')}"`);
      });
      lines[lines.length - 1] += ';';
    }

    lines.push('}');

    cells.forEach((cell, idx) => {
      const areaName = cell.name.replace(/\s+/g, '-').toLowerCase() || `area-${idx + 1}`;
      lines.push('');
      lines.push(`.${areaName} {`);
      lines.push(`  grid-area: ${areaName};`);
      lines.push('}');
    });

    return lines.join('\n');
  };

  const selected = cells.find(c => c.id === selectedCell);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-2">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Rows</label>
          <input
            type="number"
            value={rows}
            onChange={(e) => onChange({ ...data, rows: Math.max(1, parseInt(e.target.value) || 1) })}
            min={1}
            max={12}
            className="w-full px-2 py-1 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Columns</label>
          <input
            type="number"
            value={cols}
            onChange={(e) => onChange({ ...data, cols: Math.max(1, parseInt(e.target.value) || 1) })}
            min={1}
            max={12}
            className="w-full px-2 py-1 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Gap (px)</label>
          <input
            type="number"
            value={gap}
            onChange={(e) => onChange({ ...data, gap: parseInt(e.target.value) || 0 })}
            min={0}
            max={50}
            className="w-full px-2 py-1 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          />
        </div>
      </div>

      <div
        className="border border-gray-700 rounded p-2 bg-[#1a1a2e] relative"
        style={{
          display: 'grid',
          gridTemplateRows: `repeat(${rows}, 40px)`,
          gridTemplateColumns: `repeat(${cols}, 1fr)`,
          gap: `${gap}px`
        }}
      >
        {/* Grid background */}
        {Array.from({ length: rows * cols }).map((_, i) => (
          <div
            key={`bg-${i}`}
            className="border border-dashed border-gray-600 rounded"
          />
        ))}

        {/* Cells overlay */}
        {cells.map((cell, idx) => (
          <div
            key={cell.id}
            onClick={() => onChange({ ...data, selectedCell: cell.id })}
            className={`absolute rounded cursor-pointer flex items-center justify-center text-xs text-white ${
              COLORS[idx % COLORS.length]
            } ${selectedCell === cell.id ? 'ring-2 ring-blue-500' : ''}`}
            style={{
              gridRow: `${cell.row} / span ${cell.rowSpan}`,
              gridColumn: `${cell.col} / span ${cell.colSpan}`,
              top: `${(cell.row - 1) * (40 + gap) + 8}px`,
              left: `${(cell.col - 1) * ((100 / cols)) + 1}%`,
              width: `${(cell.colSpan * 100 / cols) - 2}%`,
              height: `${cell.rowSpan * 40 + (cell.rowSpan - 1) * gap}px`
            }}
          >
            {cell.name}
          </div>
        ))}
      </div>

      <button
        onClick={handleAddCell}
        className="w-full py-1.5 bg-green-600 hover:bg-green-500 text-white rounded text-sm"
      >
        + Add Grid Area
      </button>

      {selected && (
        <div className="space-y-2 p-2 bg-[#1a1a2e] rounded border border-gray-700">
          <div className="flex justify-between items-center">
            <span className="text-xs text-gray-400">Selected: {selected.name}</span>
            <button
              onClick={() => handleRemoveCell(selected.id)}
              className="text-xs text-red-400 hover:text-red-300"
            >
              Remove
            </button>
          </div>
          <input
            type="text"
            value={selected.name}
            onChange={(e) => handleCellChange(selected.id, { name: e.target.value })}
            placeholder="Area name"
            className="w-full px-2 py-1 bg-[#0d0d1a] border border-gray-600 rounded text-white text-xs"
          />
          <div className="grid grid-cols-4 gap-2 text-xs">
            <div>
              <label className="text-gray-500">Row</label>
              <input
                type="number"
                value={selected.row}
                onChange={(e) => handleCellChange(selected.id, { row: Math.max(1, parseInt(e.target.value) || 1) })}
                min={1}
                max={rows}
                className="w-full px-1 py-0.5 bg-[#0d0d1a] border border-gray-600 rounded text-white"
              />
            </div>
            <div>
              <label className="text-gray-500">Col</label>
              <input
                type="number"
                value={selected.col}
                onChange={(e) => handleCellChange(selected.id, { col: Math.max(1, parseInt(e.target.value) || 1) })}
                min={1}
                max={cols}
                className="w-full px-1 py-0.5 bg-[#0d0d1a] border border-gray-600 rounded text-white"
              />
            </div>
            <div>
              <label className="text-gray-500">RowSpan</label>
              <input
                type="number"
                value={selected.rowSpan}
                onChange={(e) => handleCellChange(selected.id, { rowSpan: Math.max(1, parseInt(e.target.value) || 1) })}
                min={1}
                max={rows - selected.row + 1}
                className="w-full px-1 py-0.5 bg-[#0d0d1a] border border-gray-600 rounded text-white"
              />
            </div>
            <div>
              <label className="text-gray-500">ColSpan</label>
              <input
                type="number"
                value={selected.colSpan}
                onChange={(e) => handleCellChange(selected.id, { colSpan: Math.max(1, parseInt(e.target.value) || 1) })}
                min={1}
                max={cols - selected.col + 1}
                className="w-full px-1 py-0.5 bg-[#0d0d1a] border border-gray-600 rounded text-white"
              />
            </div>
          </div>
        </div>
      )}

      <div className="space-y-2">
        <div className="flex justify-between items-center">
          <span className="text-xs text-gray-400">Generated CSS</span>
          <button onClick={handleCopy} className="text-xs text-blue-400 hover:text-blue-300">
            Copy
          </button>
        </div>
        <textarea
          readOnly
          value={generateCSS()}
          className="w-full h-32 px-2 py-1 bg-[#0d0d1a] border border-gray-700 rounded text-green-400 font-mono text-xs resize-none"
        />
      </div>
    </div>
  );
};

export class VisualGridBuilderTool {
  static Component = VisualGridBuilder;
}
