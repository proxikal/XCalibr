import { beforeEach, describe, it } from 'vitest';
import { aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  waitFor,
  findButtonByText,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('IndexAdvisorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('suggests index statements', async () => {
      const root = await mountWithTool('indexAdvisor', {
        table: 'users',
        columns: 'email',
        unique: false,
        output: ''
      });
      if (!root) return;
      const button = await waitFor(() => findButtonByText(root, 'Suggest Index'));
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return (toolData.indexAdvisor?.output ?? '').includes('CREATE');
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.indexAdvisor?.output ?? '';
      aiAssertIncludes({ name: 'IndexAdvisorOutput' }, output, 'CREATE');
    });
  });
});
