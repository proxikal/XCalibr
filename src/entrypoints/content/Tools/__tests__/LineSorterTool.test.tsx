import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('LineSorterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('lineSorter');
      aiAssertTruthy({ name: 'SorterMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'SorterTitle' }, text, 'Line');
    });

    it('renders sort options', async () => {
      const root = await mountWithTool('lineSorter');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'SorterSort' }, text, 'Sort');
    });

    it('renders dedupe option', async () => {
      const root = await mountWithTool('lineSorter');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'SorterDedupe' }, text, 'Remove');
    });
  });

  describe('Sorting', () => {
    it('shows sorted output', async () => {
      const root = await mountWithTool('lineSorter', {
        input: 'b\na\nc',
        output: 'a\nb\nc'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'SorterOutput' }, text, 'a');
    });
  });

  describe('Persistence', () => {
    it('persists input value', async () => {
      await mountWithTool('lineSorter', {
        input: 'line1\nline2'
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { input?: string }>;
        return toolData.lineSorter?.input === 'line1\nline2';
      });
      aiAssertTruthy({ name: 'SorterPersist' }, stored);
    });
  });
});
