import { beforeEach, describe, it } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  waitFor,
  findButtonByText,
  queryAllByText
} from '../../../__tests__/integration-test-utils';

describe('AccessibilityAuditTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('runs accessibility audit', async () => {
      document.body.innerHTML = '<img src="/test.png" />';
      const root = await mountWithTool('accessibilityAudit');
      if (!root) return;
      const button = await waitFor(() => findButtonByText(root, 'Run Audit'));
      aiAssertTruthy({ name: 'AccessibilityAuditButton' }, button);
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const issue = await waitFor(() =>
        queryAllByText(root, 'Image missing alt text')[0]
      );
      aiAssertTruthy({ name: 'AccessibilityAuditIssue' }, issue);
    });
  });
});
