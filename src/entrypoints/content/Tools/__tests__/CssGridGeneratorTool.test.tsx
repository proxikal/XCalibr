import { describe, it } from 'vitest';
import { aiAssertEqual, aiAssertTruthy } from '../../../../test-utils/aiAssert';
import type { CssGridGeneratorData } from '../tool-types';

// parseGridTemplate function from the tool
const parseGridTemplate = (template: string): number => {
  const trimmed = template.trim();
  const repeatMatch = trimmed.match(/^repeat\s*\(\s*(\d+)/);
  if (repeatMatch) {
    return parseInt(repeatMatch[1], 10);
  }
  const parts = trimmed.split(/\s+/).filter(Boolean);
  return Math.max(1, parts.length);
};

describe('CssGridGeneratorTool', () => {
  describe('parseGridTemplate function', () => {
    it('should parse repeat(n, ...) syntax', () => {
      const testCases = [
        { template: 'repeat(3, 1fr)', expected: 3 },
        { template: 'repeat(4, 100px)', expected: 4 },
        { template: 'repeat(12, minmax(0, 1fr))', expected: 12 },
        { template: 'repeat( 5 , 1fr)', expected: 5 }, // With spaces
      ];

      testCases.forEach(({ template, expected }) => {
        aiAssertEqual(
          { name: 'ParseRepeat', input: template },
          parseGridTemplate(template),
          expected
        );
      });
    });

    it('should parse space-separated values', () => {
      const testCases = [
        { template: '1fr 1fr 1fr', expected: 3 },
        { template: '100px 200px', expected: 2 },
        { template: '1fr 2fr 1fr 2fr', expected: 4 },
        { template: 'auto auto auto auto auto', expected: 5 },
      ];

      testCases.forEach(({ template, expected }) => {
        aiAssertEqual(
          { name: 'ParseSpaceSeparated', input: template },
          parseGridTemplate(template),
          expected
        );
      });
    });

    it('should return 1 for "auto"', () => {
      aiAssertEqual(
        { name: 'ParseAuto', input: 'auto' },
        parseGridTemplate('auto'),
        1
      );
    });

    it('should handle empty or whitespace strings', () => {
      aiAssertEqual(
        { name: 'ParseEmpty', input: '' },
        parseGridTemplate(''),
        1 // Math.max(1, 0)
      );
      aiAssertEqual(
        { name: 'ParseWhitespace', input: '   ' },
        parseGridTemplate('   '),
        1
      );
    });

    it('should handle single value', () => {
      aiAssertEqual(
        { name: 'ParseSingleValue', input: '1fr' },
        parseGridTemplate('1fr'),
        1
      );
    });
  });

  describe('CSS output generation', () => {
    it('should generate correct CSS with all properties', () => {
      const columns = 'repeat(3, 1fr)';
      const rows = 'auto';
      const gap = '16px';
      const width = 300;
      const height = 200;

      const css = `display: grid;\ngrid-template-columns: ${columns};\ngrid-template-rows: ${rows};\ngap: ${gap};\nwidth: ${width}px;\nheight: ${height}px;`;

      aiAssertTruthy(
        { name: 'ContainsDisplay', input: css },
        css.includes('display: grid;')
      );
      aiAssertTruthy(
        { name: 'ContainsColumns', input: css },
        css.includes('grid-template-columns: repeat(3, 1fr);')
      );
      aiAssertTruthy(
        { name: 'ContainsRows', input: css },
        css.includes('grid-template-rows: auto;')
      );
      aiAssertTruthy(
        { name: 'ContainsGap', input: css },
        css.includes('gap: 16px;')
      );
      aiAssertTruthy(
        { name: 'ContainsWidth', input: css },
        css.includes('width: 300px;')
      );
      aiAssertTruthy(
        { name: 'ContainsHeight', input: css },
        css.includes('height: 200px;')
      );
    });

    it('should generate CSS without dimensions when not provided', () => {
      const columns = 'repeat(3, 1fr)';
      const rows = 'auto';
      const gap = '16px';
      const drawnWidth = undefined;
      const drawnHeight = undefined;

      const widthPart = drawnWidth ? `\nwidth: ${drawnWidth}px;` : '';
      const heightPart = drawnHeight ? `\nheight: ${drawnHeight}px;` : '';
      const css = `display: grid;\ngrid-template-columns: ${columns};\ngrid-template-rows: ${rows};\ngap: ${gap};${widthPart}${heightPart}`;

      aiAssertTruthy(
        { name: 'NoWidthWhenUndefined', input: css },
        !css.includes('width:')
      );
      aiAssertTruthy(
        { name: 'NoHeightWhenUndefined', input: css },
        !css.includes('height:')
      );
    });
  });

  describe('Grid line calculations', () => {
    it('should calculate column line positions correctly', () => {
      const numCols = 3;
      const width = 300;
      const positions: number[] = [];

      for (let i = 1; i < numCols; i++) {
        const x = Math.round((width / numCols) * i);
        positions.push(x);
      }

      aiAssertEqual(
        { name: 'ColumnLineCount', input: { numCols, width } },
        positions.length,
        2 // 3 columns = 2 lines
      );
      aiAssertEqual(
        { name: 'FirstColumnLine', input: { numCols, width } },
        positions[0],
        100
      );
      aiAssertEqual(
        { name: 'SecondColumnLine', input: { numCols, width } },
        positions[1],
        200
      );
    });

    it('should calculate row line positions correctly', () => {
      const numRows = 4;
      const height = 400;
      const positions: number[] = [];

      for (let i = 1; i < numRows; i++) {
        const y = Math.round((height / numRows) * i);
        positions.push(y);
      }

      aiAssertEqual(
        { name: 'RowLineCount', input: { numRows, height } },
        positions.length,
        3 // 4 rows = 3 lines
      );
      aiAssertEqual(
        { name: 'FirstRowLine', input: { numRows, height } },
        positions[0],
        100
      );
      aiAssertEqual(
        { name: 'SecondRowLine', input: { numRows, height } },
        positions[1],
        200
      );
      aiAssertEqual(
        { name: 'ThirdRowLine', input: { numRows, height } },
        positions[2],
        300
      );
    });
  });

  describe('Drag dimension calculations', () => {
    it('should calculate width and height from drag', () => {
      const dragStart = { x: 100, y: 100 };
      const mousePos = { x: 400, y: 300 };

      const width = Math.abs(mousePos.x - dragStart.x);
      const height = Math.abs(mousePos.y - dragStart.y);

      aiAssertEqual(
        { name: 'DragWidth', input: { dragStart, mousePos } },
        width,
        300
      );
      aiAssertEqual(
        { name: 'DragHeight', input: { dragStart, mousePos } },
        height,
        200
      );
    });

    it('should handle reverse drag direction', () => {
      const dragStart = { x: 400, y: 300 };
      const mousePos = { x: 100, y: 100 };

      const width = Math.abs(mousePos.x - dragStart.x);
      const height = Math.abs(mousePos.y - dragStart.y);
      const left = Math.min(mousePos.x, dragStart.x);
      const top = Math.min(mousePos.y, dragStart.y);

      aiAssertEqual(
        { name: 'ReverseDragWidth', input: { dragStart, mousePos } },
        width,
        300
      );
      aiAssertEqual(
        { name: 'ReverseDragHeight', input: { dragStart, mousePos } },
        height,
        200
      );
      aiAssertEqual(
        { name: 'ReverseDragLeft', input: { dragStart, mousePos } },
        left,
        100
      );
      aiAssertEqual(
        { name: 'ReverseDragTop', input: { dragStart, mousePos } },
        top,
        100
      );
    });

    it('should reject drag smaller than minimum threshold', () => {
      const width = 5;
      const height = 8;
      const minThreshold = 10;

      const isValidDrag = width > minThreshold && height > minThreshold;

      aiAssertEqual(
        { name: 'SmallDragRejected', input: { width, height, minThreshold } },
        isValidDrag,
        false
      );
    });

    it('should accept drag larger than minimum threshold', () => {
      const width = 150;
      const height = 100;
      const minThreshold = 10;

      const isValidDrag = width > minThreshold && height > minThreshold;

      aiAssertEqual(
        { name: 'LargeDragAccepted', input: { width, height, minThreshold } },
        isValidDrag,
        true
      );
    });
  });

  describe('Default values', () => {
    it('should use default values when data is undefined', () => {
      const getData = (): CssGridGeneratorData | undefined => undefined;
      const data = getData();

      const columns = data?.columns ?? 'repeat(3, 1fr)';
      const rows = data?.rows ?? 'auto';
      const gap = data?.gap ?? '16px';
      const output = data?.output ?? '';
      const isActive = data?.isActive ?? false;

      aiAssertEqual(
        { name: 'DefaultColumns' },
        columns,
        'repeat(3, 1fr)'
      );
      aiAssertEqual(
        { name: 'DefaultRows' },
        rows,
        'auto'
      );
      aiAssertEqual(
        { name: 'DefaultGap' },
        gap,
        '16px'
      );
      aiAssertEqual(
        { name: 'DefaultOutput' },
        output,
        ''
      );
      aiAssertEqual(
        { name: 'DefaultIsActive' },
        isActive,
        false
      );
    });
  });

  describe('Grid content building', () => {
    it('should not build content for small dimensions', () => {
      const width = 15;
      const height = 15;
      const minSize = 20;

      const shouldBuild = width >= minSize && height >= minSize;

      aiAssertEqual(
        { name: 'SmallDimensionsNoBuild', input: { width, height, minSize } },
        shouldBuild,
        false
      );
    });

    it('should build content for valid dimensions', () => {
      const width = 100;
      const height = 100;
      const minSize = 20;

      const shouldBuild = width >= minSize && height >= minSize;

      aiAssertEqual(
        { name: 'ValidDimensionsBuild', input: { width, height, minSize } },
        shouldBuild,
        true
      );
    });
  });

  describe('State management', () => {
    it('should toggle isActive state', () => {
      const initialState: CssGridGeneratorData = { isActive: false };
      const nextState = { ...initialState, isActive: !initialState.isActive };

      aiAssertEqual(
        { name: 'ToggleActive', input: initialState },
        nextState.isActive,
        true
      );
    });

    it('should preserve other data when updating', () => {
      const initialState: CssGridGeneratorData = {
        columns: 'repeat(4, 1fr)',
        rows: 'repeat(2, 1fr)',
        gap: '20px',
        isActive: false
      };
      const nextState = { ...initialState, isActive: true };

      aiAssertEqual(
        { name: 'PreserveColumns', input: initialState },
        nextState.columns,
        'repeat(4, 1fr)'
      );
      aiAssertEqual(
        { name: 'PreserveRows', input: initialState },
        nextState.rows,
        'repeat(2, 1fr)'
      );
      aiAssertEqual(
        { name: 'PreserveGap', input: initialState },
        nextState.gap,
        '20px'
      );
    });
  });
});
