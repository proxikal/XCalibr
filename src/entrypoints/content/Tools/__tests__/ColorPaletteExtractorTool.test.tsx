import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('ColorPaletteExtractorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('colorPaletteExtractor');
      aiAssertTruthy({ name: 'PaletteMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'PaletteTitle' }, text, 'Color Palette');
    });

    it('renders upload instructions', async () => {
      const root = await mountWithTool('colorPaletteExtractor');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'PaletteUpload' }, text, 'image');
    });

    it('renders color count option', async () => {
      const root = await mountWithTool('colorPaletteExtractor');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'PaletteCount' }, text, 'Colors');
    });
  });

  describe('Colors Display', () => {
    it('shows colors when extracted', async () => {
      const root = await mountWithTool('colorPaletteExtractor', {
        colors: ['#ff0000', '#00ff00', '#0000ff']
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'PaletteColors' }, text, '#');
    });
  });

  describe('Persistence', () => {
    it('persists color count', async () => {
      await mountWithTool('colorPaletteExtractor', {
        colorCount: 8
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { colorCount?: number }>;
        return toolData.colorPaletteExtractor?.colorCount === 8;
      });
      aiAssertTruthy({ name: 'PalettePersist' }, stored);
    });
  });
});
