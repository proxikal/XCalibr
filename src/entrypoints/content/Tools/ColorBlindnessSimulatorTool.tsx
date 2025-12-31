import React from 'react';

export type ColorBlindnessSimulatorData = {
  simulationType?: 'normal' | 'protanopia' | 'deuteranopia' | 'tritanopia' | 'achromatopsia';
  isActive?: boolean;
};

type Props = {
  data: ColorBlindnessSimulatorData | undefined;
  onChange: (data: ColorBlindnessSimulatorData) => void;
};

const SIMULATION_TYPES = [
  { id: 'normal', name: 'Normal Vision', description: 'No simulation applied' },
  { id: 'protanopia', name: 'Protanopia', description: 'Red-blindness (~1% of males)' },
  { id: 'deuteranopia', name: 'Deuteranopia', description: 'Green-blindness (~6% of males)' },
  { id: 'tritanopia', name: 'Tritanopia', description: 'Blue-blindness (very rare)' },
  { id: 'achromatopsia', name: 'Achromatopsia', description: 'Complete color blindness' }
] as const;

// Color matrix values for different types of color blindness
const COLOR_MATRICES: Record<string, string> = {
  protanopia: `
    0.567, 0.433, 0,     0, 0
    0.558, 0.442, 0,     0, 0
    0,     0.242, 0.758, 0, 0
    0,     0,     0,     1, 0
  `,
  deuteranopia: `
    0.625, 0.375, 0,   0, 0
    0.7,   0.3,   0,   0, 0
    0,     0.3,   0.7, 0, 0
    0,     0,     0,   1, 0
  `,
  tritanopia: `
    0.95, 0.05,  0,     0, 0
    0,    0.433, 0.567, 0, 0
    0,    0.475, 0.525, 0, 0
    0,    0,     0,     1, 0
  `,
  achromatopsia: `
    0.299, 0.587, 0.114, 0, 0
    0.299, 0.587, 0.114, 0, 0
    0.299, 0.587, 0.114, 0, 0
    0,     0,     0,     1, 0
  `
};

const ColorBlindnessSimulator: React.FC<Props> = ({ data, onChange }) => {
  const simulationType = data?.simulationType ?? 'normal';
  const isActive = data?.isActive ?? false;

  const handleApply = () => {
    if (simulationType === 'normal') {
      handleRemove();
      return;
    }

    // Remove existing filter
    handleRemove();

    // Create SVG filter
    const svgNS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(svgNS, 'svg');
    svg.setAttribute('id', 'xcalibr-colorblind-filter');
    svg.style.cssText = 'position:absolute;width:0;height:0;pointer-events:none;';

    const defs = document.createElementNS(svgNS, 'defs');
    const filter = document.createElementNS(svgNS, 'filter');
    filter.setAttribute('id', 'colorblind-matrix');

    const feColorMatrix = document.createElementNS(svgNS, 'feColorMatrix');
    feColorMatrix.setAttribute('type', 'matrix');
    feColorMatrix.setAttribute('values', COLOR_MATRICES[simulationType] || '');

    filter.appendChild(feColorMatrix);
    defs.appendChild(filter);
    svg.appendChild(defs);
    document.body.appendChild(svg);

    // Apply filter to body
    document.documentElement.style.filter = 'url(#colorblind-matrix)';
    document.documentElement.style.height = '100%';

    onChange({ ...data, isActive: true });
  };

  const handleRemove = () => {
    const existingSvg = document.getElementById('xcalibr-colorblind-filter');
    if (existingSvg) {
      existingSvg.remove();
    }
    document.documentElement.style.filter = '';
    onChange({ ...data, isActive: false });
  };

  const handleTypeChange = (type: ColorBlindnessSimulatorData['simulationType']) => {
    onChange({ ...data, simulationType: type });
    if (isActive && type !== 'normal') {
      // Re-apply with new type
      setTimeout(() => handleApply(), 0);
    } else if (type === 'normal') {
      handleRemove();
    }
  };

  const currentType = SIMULATION_TYPES.find(t => t.id === simulationType);

  return (
    <div className="space-y-4">
      <div className="text-xs text-gray-400">
        Simulates how the page appears to people with different types of color vision deficiency.
      </div>

      <div className="space-y-2">
        {SIMULATION_TYPES.map((type) => (
          <button
            key={type.id}
            onClick={() => handleTypeChange(type.id as ColorBlindnessSimulatorData['simulationType'])}
            className={`w-full flex items-start gap-3 p-2 rounded text-left ${
              simulationType === type.id
                ? 'bg-blue-600/30 border border-blue-500'
                : 'bg-[#1a1a2e] border border-gray-700 hover:border-gray-600'
            }`}
          >
            <div className={`w-4 h-4 rounded-full border-2 mt-0.5 ${
              simulationType === type.id ? 'border-blue-500 bg-blue-500' : 'border-gray-500'
            }`} />
            <div>
              <div className="text-sm text-white">{type.name}</div>
              <div className="text-xs text-gray-400">{type.description}</div>
            </div>
          </button>
        ))}
      </div>

      <div className="flex gap-2">
        <button
          onClick={handleApply}
          disabled={simulationType === 'normal'}
          className={`flex-1 py-2 rounded text-sm ${
            isActive
              ? 'bg-yellow-600 hover:bg-yellow-500 text-white'
              : 'bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white'
          }`}
        >
          {isActive ? 'Update Simulation' : 'Apply to Page'}
        </button>
        <button
          onClick={handleRemove}
          disabled={!isActive}
          className="flex-1 py-2 bg-red-600 hover:bg-red-500 disabled:bg-gray-600 text-white rounded text-sm"
        >
          Reset / Disable
        </button>
      </div>

      {isActive && simulationType !== 'normal' && (
        <div className="text-xs text-yellow-400 bg-yellow-900/20 p-2 rounded">
          Active: {currentType?.name} simulation is applied to the page
        </div>
      )}

      <div className="text-xs text-gray-500">
        Note: This filter applies to the entire page. Disable before taking screenshots.
      </div>
    </div>
  );
};

export class ColorBlindnessSimulatorTool {
  static Component = ColorBlindnessSimulator;
}
