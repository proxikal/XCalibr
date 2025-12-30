import { beforeEach, describe, it } from 'vitest';
import { aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('SqlFormatterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('formats SQL', async () => {
      const root = await mountWithTool('sqlFormatter', {
        input: 'select * from users where id=1',
        output: ''
      });
      if (!root) return;
      const button = findButtonByText(root, 'Format SQL');
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return (toolData.sqlFormatter?.output ?? '').includes('SELECT');
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.sqlFormatter?.output ?? '';
      aiAssertIncludes({ name: 'SqlFormatterOutput' }, output, 'SELECT');
    });
  });
});
