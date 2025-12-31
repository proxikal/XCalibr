import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('CsvToJsonTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('csvToJson');
      aiAssertTruthy({ name: 'CsvMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CsvTitle' }, text, 'CSV');
    });

    it('renders convert button', async () => {
      const root = await mountWithTool('csvToJson');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CsvConvert' }, text, 'Convert');
    });

    it('renders delimiter option', async () => {
      const root = await mountWithTool('csvToJson');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CsvDelimiter' }, text, 'Delimiter');
    });
  });

  describe('Conversion', () => {
    it('shows output when converted', async () => {
      const root = await mountWithTool('csvToJson', {
        input: 'name,age\nJohn,30',
        output: '[{"name":"John","age":"30"}]'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CsvOutput' }, text, 'John');
    });
  });

  describe('Persistence', () => {
    it('persists input value', async () => {
      await mountWithTool('csvToJson', {
        input: 'a,b,c'
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { input?: string }>;
        return toolData.csvToJson?.input === 'a,b,c';
      });
      aiAssertTruthy({ name: 'CsvPersist' }, stored);
    });
  });
});
