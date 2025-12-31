import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('BorderRadiusGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('borderRadiusGenerator');
      aiAssertTruthy({ name: 'BorderRadiusMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'BorderRadiusTitle' }, text, 'Border Radius Generator');
    });

    it('renders corner controls', async () => {
      const root = await mountWithTool('borderRadiusGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'BorderRadiusTL' }, text, 'Top Left');
      aiAssertIncludes({ name: 'BorderRadiusTR' }, text, 'Top Right');
      aiAssertIncludes({ name: 'BorderRadiusBL' }, text, 'Bottom Left');
      aiAssertIncludes({ name: 'BorderRadiusBR' }, text, 'Bottom Right');
    });

    it('renders unit selector', async () => {
      const root = await mountWithTool('borderRadiusGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'BorderRadiusPx' }, text, 'px');
    });

    it('renders Copy button', async () => {
      const root = await mountWithTool('borderRadiusGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'BorderRadiusCopy' }, text, 'Copy');
    });
  });

  describe('CSS Output', () => {
    it('generates border-radius CSS', async () => {
      const root = await mountWithTool('borderRadiusGenerator', {
        topLeft: 10,
        topRight: 10,
        bottomRight: 10,
        bottomLeft: 10
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'BorderRadiusCSS' }, text, 'border-radius:');
    });

    it('shows shorthand for equal values', async () => {
      const root = await mountWithTool('borderRadiusGenerator', {
        topLeft: 20,
        topRight: 20,
        bottomRight: 20,
        bottomLeft: 20,
        unit: 'px'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'BorderRadiusShorthand' }, text, '20px');
    });
  });

  describe('Persistence', () => {
    it('persists corner values', async () => {
      const root = await mountWithTool('borderRadiusGenerator', {
        topLeft: 25
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { topLeft?: number }>;
        return toolData.borderRadiusGenerator?.topLeft === 25;
      });
      aiAssertTruthy({ name: 'BorderRadiusPersist' }, stored);
    });
  });
});
