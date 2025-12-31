import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('BoxShadowGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('boxShadowGenerator');
      aiAssertTruthy({ name: 'BoxShadowMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'BoxShadowTitle' }, text, 'Box Shadow Generator');
    });

    it('renders offset controls', async () => {
      const root = await mountWithTool('boxShadowGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'BoxShadowHOffset' }, text, 'Horizontal');
      aiAssertIncludes({ name: 'BoxShadowVOffset' }, text, 'Vertical');
    });

    it('renders blur and spread controls', async () => {
      const root = await mountWithTool('boxShadowGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'BoxShadowBlur' }, text, 'Blur');
      aiAssertIncludes({ name: 'BoxShadowSpread' }, text, 'Spread');
    });

    it('renders Copy button', async () => {
      const root = await mountWithTool('boxShadowGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'BoxShadowCopy' }, text, 'Copy');
    });
  });

  describe('CSS Output', () => {
    it('generates box-shadow CSS', async () => {
      const root = await mountWithTool('boxShadowGenerator', {
        horizontalOffset: 5,
        verticalOffset: 5,
        blurRadius: 10,
        spreadRadius: 0,
        color: 'rgba(0,0,0,0.25)'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'BoxShadowCSS' }, text, 'box-shadow:');
    });

    it('includes inset when enabled', async () => {
      const root = await mountWithTool('boxShadowGenerator', {
        horizontalOffset: 5,
        verticalOffset: 5,
        blurRadius: 10,
        spreadRadius: 0,
        color: 'rgba(0,0,0,0.25)',
        inset: true
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'BoxShadowInset' }, text, 'inset');
    });
  });

  describe('Persistence', () => {
    it('persists blur radius', async () => {
      const root = await mountWithTool('boxShadowGenerator', {
        blurRadius: 20
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { blurRadius?: number }>;
        return toolData.boxShadowGenerator?.blurRadius === 20;
      });
      aiAssertTruthy({ name: 'BoxShadowPersist' }, stored);
    });
  });
});
