import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('CssGradientGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('cssGradientGenerator');
      aiAssertTruthy({ name: 'GradientMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'GradientTitle' }, text, 'CSS Gradient Generator');
    });

    it('renders gradient type selector', async () => {
      const root = await mountWithTool('cssGradientGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'GradientLinear' }, text, 'linear');
      aiAssertIncludes({ name: 'GradientRadial' }, text, 'radial');
    });

    it('renders color stops', async () => {
      const root = await mountWithTool('cssGradientGenerator');
      const colorInputs = root?.querySelectorAll('input[type="color"]') || [];
      aiAssertTruthy({ name: 'GradientColorInputs' }, colorInputs.length >= 2);
    });

    it('renders Copy button', async () => {
      const root = await mountWithTool('cssGradientGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'GradientCopy' }, text, 'Copy');
    });
  });

  describe('CSS Output', () => {
    it('generates linear-gradient CSS', async () => {
      const root = await mountWithTool('cssGradientGenerator', {
        type: 'linear',
        angle: 90,
        colorStops: [
          { color: '#ff0000', position: 0 },
          { color: '#0000ff', position: 100 }
        ]
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'GradientLinearCSS' }, text, 'linear-gradient');
    });

    it('generates radial-gradient CSS', async () => {
      const root = await mountWithTool('cssGradientGenerator', {
        type: 'radial',
        colorStops: [
          { color: '#ff0000', position: 0 },
          { color: '#0000ff', position: 100 }
        ]
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'GradientRadialCSS' }, text, 'radial-gradient');
    });
  });

  describe('Persistence', () => {
    it('persists gradient type', async () => {
      await mountWithTool('cssGradientGenerator', {
        type: 'radial'
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { type?: string }>;
        return toolData.cssGradientGenerator?.type === 'radial';
      });
      aiAssertTruthy({ name: 'GradientPersist' }, stored);
    });
  });
});
