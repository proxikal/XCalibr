import { beforeEach, describe, it } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText
} from '../../../__tests__/integration-test-utils';

describe('DomSnapshotTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('captures sanitized DOM snapshot', async () => {
      document.body.innerHTML = '<div>Hello</div><script>evil()</script>';
      const root = await mountWithTool('domSnapshot');
      if (!root) return;
      const captureButton = findButtonByText(root, 'Capture');
      captureButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const output = root.querySelector(
        'textarea[placeholder="Snapshot will appear here..."]'
      ) as HTMLTextAreaElement | null;
      aiAssertTruthy(
        { name: 'DomSnapshotSanitized' },
        output?.value?.includes('<script>') === false
      );
    });
  });
});
