import { beforeEach, describe, it } from 'vitest';
import { aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('JsonPathTesterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('runs JSON path tester', async () => {
      const root = await mountWithTool('jsonPathTester', {
        path: '$.items[0].name',
        input: '{"items":[{"name":"ok"}]}',
        output: '',
        error: ''
      });
      if (!root) return;
      const runButton = findButtonByText(root, 'Run Path');
      runButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return (toolData.jsonPathTester?.output ?? '').includes('ok');
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.jsonPathTester?.output ?? '';
      aiAssertIncludes({ name: 'JsonPathOutput' }, output, 'ok');
    });
  });
});
