import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('CssFilterGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('cssFilterGenerator');
      aiAssertTruthy({ name: 'FilterMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'FilterTitle' }, text, 'CSS Filter Generator');
    });

    it('renders blur control', async () => {
      const root = await mountWithTool('cssFilterGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'FilterBlur' }, text, 'Blur');
    });

    it('renders brightness control', async () => {
      const root = await mountWithTool('cssFilterGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'FilterBrightness' }, text, 'Brightness');
    });

    it('renders contrast control', async () => {
      const root = await mountWithTool('cssFilterGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'FilterContrast' }, text, 'Contrast');
    });

    it('renders Copy button', async () => {
      const root = await mountWithTool('cssFilterGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'FilterCopy' }, text, 'Copy');
    });
  });

  describe('CSS Output', () => {
    it('generates filter CSS', async () => {
      const root = await mountWithTool('cssFilterGenerator', {
        blur: 5,
        brightness: 100,
        contrast: 100
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'FilterCSS' }, text, 'filter:');
    });
  });

  describe('Persistence', () => {
    it('persists blur value', async () => {
      await mountWithTool('cssFilterGenerator', {
        blur: 10
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { blur?: number }>;
        return toolData.cssFilterGenerator?.blur === 10;
      });
      aiAssertTruthy({ name: 'FilterPersist' }, stored);
    });
  });
});
