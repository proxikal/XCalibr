import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('TextStatisticsTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('textStatistics');
      aiAssertTruthy({ name: 'StatsMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'StatsTitle' }, text, 'Text Statistics');
    });

    it('renders word count', async () => {
      const root = await mountWithTool('textStatistics');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'StatsWords' }, text, 'Words');
    });

    it('renders character count', async () => {
      const root = await mountWithTool('textStatistics');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'StatsChars' }, text, 'Character');
    });
  });

  describe('Statistics', () => {
    it('calculates stats correctly', async () => {
      const root = await mountWithTool('textStatistics', {
        input: 'Hello World',
        stats: { words: 2, characters: 11 }
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'StatsCalc' }, text, '2');
    });
  });

  describe('Persistence', () => {
    it('persists input value', async () => {
      await mountWithTool('textStatistics', {
        input: 'test text'
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { input?: string }>;
        return toolData.textStatistics?.input === 'test text';
      });
      aiAssertTruthy({ name: 'StatsPersist' }, stored);
    });
  });
});
