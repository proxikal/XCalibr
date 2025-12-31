import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('ClampCalculatorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('clampCalculator');
      aiAssertTruthy({ name: 'ClampMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'ClampTitle' }, text, 'Clamp');
    });

    it('renders viewport inputs', async () => {
      const root = await mountWithTool('clampCalculator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'ClampViewport' }, text, 'Viewport');
    });

    it('renders font size inputs', async () => {
      const root = await mountWithTool('clampCalculator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'ClampFont' }, text, 'Font');
    });

    it('renders copy button', async () => {
      const root = await mountWithTool('clampCalculator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'ClampCopy' }, text, 'Copy');
    });
  });

  describe('Output', () => {
    it('generates clamp output', async () => {
      const root = await mountWithTool('clampCalculator', {
        minViewport: 320,
        maxViewport: 1200,
        minFontSize: 16,
        maxFontSize: 24
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'ClampOutput' }, text, 'clamp');
    });
  });

  describe('Persistence', () => {
    it('persists min font size', async () => {
      await mountWithTool('clampCalculator', {
        minFontSize: 14
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { minFontSize?: number }>;
        return toolData.clampCalculator?.minFontSize === 14;
      });
      aiAssertTruthy({ name: 'ClampPersist' }, stored);
    });
  });
});
