import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('FaviconGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('faviconGenerator');
      aiAssertTruthy({ name: 'FaviconMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'FaviconTitle' }, text, 'Favicon Generator');
    });

    it('renders icon character input', async () => {
      const root = await mountWithTool('faviconGenerator');
      const inputs = root?.querySelectorAll('input') || [];
      const charInput = Array.from(inputs).find(
        (i) => i.placeholder?.toLowerCase().includes('emoji') || i.placeholder?.toLowerCase().includes('character')
      );
      aiAssertTruthy({ name: 'FaviconCharInput' }, charInput);
    });

    it('renders background color picker', async () => {
      const root = await mountWithTool('faviconGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'FaviconBgColor' }, text, 'Background');
    });

    it('renders Generate button', async () => {
      const root = await mountWithTool('faviconGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'FaviconGenerate' }, text, 'Generate');
    });
  });

  describe('Preview', () => {
    it('shows favicon preview canvas', async () => {
      const root = await mountWithTool('faviconGenerator', {
        character: '🔥'
      });
      const canvas = root?.querySelector('canvas');
      aiAssertTruthy({ name: 'FaviconCanvas' }, canvas);
    });

    it('shows size options', async () => {
      const root = await mountWithTool('faviconGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'FaviconSize16' }, text, '16');
      aiAssertIncludes({ name: 'FaviconSize32' }, text, '32');
    });
  });

  describe('Persistence', () => {
    it('persists character value', async () => {
      await mountWithTool('faviconGenerator', {
        character: '⭐'
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { character?: string }>;
        return toolData.faviconGenerator?.character === '⭐';
      });
      aiAssertTruthy({ name: 'FaviconPersist' }, stored);
    });
  });
});
