import { beforeEach, describe, it } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('FirebaseRulesLinterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('lints Firebase rules', async () => {
      const root = await mountWithTool('firebaseRulesLinter', {
        input: '{"rules":{".read":true}}',
        warnings: [],
        error: ''
      });
      if (!root) return;
      const button = findButtonByText(root, 'Lint Rules');
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { warnings?: string[] }>;
        return (toolData.firebaseRulesLinter?.warnings ?? []).length > 0;
      });
      const warnings = (stored?.toolData as Record<string, { warnings?: string[] }> | undefined)
        ?.firebaseRulesLinter?.warnings ?? [];
      aiAssertTruthy({ name: 'FirebaseRulesWarning', state: warnings }, warnings.length > 0);
    });
  });
});
