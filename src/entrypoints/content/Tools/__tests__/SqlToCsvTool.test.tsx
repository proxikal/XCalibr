import { beforeEach, describe, it } from 'vitest';
import { aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('SqlToCsvTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('converts SQL result JSON to CSV', async () => {
      const root = await mountWithTool('sqlToCsv', {
        input: '[{"a":1}]',
        output: ''
      });
      if (!root) return;
      const convertButton = findButtonByText(root, 'Convert');
      convertButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return (toolData.sqlToCsv?.output ?? '').includes('a');
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.sqlToCsv?.output ?? '';
      aiAssertIncludes({ name: 'SqlToCsvOutput' }, output, 'a');
    });
  });
});
