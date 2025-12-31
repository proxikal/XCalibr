import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('ListRandomizerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('listRandomizer');
      aiAssertTruthy({ name: 'RandomMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'RandomTitle' }, text, 'List Randomizer');
    });

    it('renders shuffle button', async () => {
      const root = await mountWithTool('listRandomizer');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'RandomShuffle' }, text, 'Shuffle');
    });

    it('renders pick winner option', async () => {
      const root = await mountWithTool('listRandomizer');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'RandomPick' }, text, 'Pick');
    });
  });

  describe('Randomization', () => {
    it('shows winner when picked', async () => {
      const root = await mountWithTool('listRandomizer', {
        input: 'a\nb\nc',
        winner: 'b'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'RandomWinner' }, text, 'Winner');
    });
  });

  describe('Persistence', () => {
    it('persists input value', async () => {
      await mountWithTool('listRandomizer', {
        input: 'item1\nitem2'
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { input?: string }>;
        return toolData.listRandomizer?.input === 'item1\nitem2';
      });
      aiAssertTruthy({ name: 'RandomPersist' }, stored);
    });
  });
});
