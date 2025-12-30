import { beforeEach, describe, it } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('FlexboxInspectorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('inspects flexbox styles', async () => {
      document.body.innerHTML = '<div class="flex-target" style="display:flex; gap: 8px;"></div>';
      const root = await mountWithTool('flexboxInspector', {
        selector: '.flex-target',
        output: []
      });
      if (!root) return;
      const button = findButtonByText(root, 'Inspect');
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string[] }>;
        return (toolData.flexboxInspector?.output ?? []).some((entry) =>
          entry.includes('display: flex')
        );
      });
      const output = (stored?.toolData as Record<string, { output?: string[] }> | undefined)
        ?.flexboxInspector?.output ?? [];
      aiAssertTruthy({ name: 'FlexboxInspectorOutput', state: output }, output.length > 0);
    });
  });
});
