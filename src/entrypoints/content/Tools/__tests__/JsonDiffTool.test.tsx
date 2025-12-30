import { beforeEach, describe, it } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  waitFor,
  findButtonByText,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('JsonDiffTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('diffs JSON', async () => {
      const root = await mountWithTool('jsonDiff', {
        left: '{"a":1}',
        right: '{"a":2}',
        diff: [],
        error: ''
      });
      if (!root) return;
      const compareButton = await waitFor(() => findButtonByText(root, 'Compare'));
      compareButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { diff?: string[] }>;
        return (toolData.jsonDiff?.diff ?? []).some((entry) => entry.includes('$.a'));
      });
      const diff = (stored?.toolData as Record<string, { diff?: string[] }> | undefined)
        ?.jsonDiff?.diff ?? [];
      aiAssertTruthy({ name: 'JsonDiffOutput', state: diff }, diff.length > 0);
    });
  });
});
