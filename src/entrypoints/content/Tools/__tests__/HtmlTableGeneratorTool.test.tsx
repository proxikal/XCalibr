import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('HtmlTableGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('htmlTableGenerator');
      aiAssertTruthy({ name: 'TableMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'TableTitle' }, text, 'HTML Table Generator');
    });

    it('renders rows control', async () => {
      const root = await mountWithTool('htmlTableGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'TableRows' }, text, 'Rows');
    });

    it('renders columns control', async () => {
      const root = await mountWithTool('htmlTableGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'TableColumns' }, text, 'Columns');
    });

    it('renders Copy button', async () => {
      const root = await mountWithTool('htmlTableGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'TableCopy' }, text, 'Copy');
    });
  });

  describe('HTML Output', () => {
    it('generates table HTML', async () => {
      const root = await mountWithTool('htmlTableGenerator', {
        rows: 3,
        columns: 3
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'TableHTML' }, text, '<table');
    });

    it('includes header when enabled', async () => {
      const root = await mountWithTool('htmlTableGenerator', {
        rows: 3,
        columns: 2,
        includeHeader: true
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'TableHeader' }, text, '<th');
    });
  });

  describe('Persistence', () => {
    it('persists rows value', async () => {
      await mountWithTool('htmlTableGenerator', {
        rows: 5
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { rows?: number }>;
        return toolData.htmlTableGenerator?.rows === 5;
      });
      aiAssertTruthy({ name: 'TablePersist' }, stored);
    });
  });
});
