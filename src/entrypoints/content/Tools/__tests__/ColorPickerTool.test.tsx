import { beforeEach, describe, it } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  waitFor,
  findButtonByText
} from '../../../__tests__/integration-test-utils';

describe('ColorPickerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('copies color in Color Picker', async () => {
      const root = await mountWithTool('colorPicker');
      if (!root) return;
      const copyButton = await waitFor(() => findButtonByText(root, 'Copy'));
      aiAssertTruthy({ name: 'ColorPickerCopyButton' }, copyButton);
      copyButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      aiAssertTruthy(
        { name: 'ColorPickerClipboard' },
        (navigator.clipboard.writeText as unknown as { mock: { calls: unknown[] } }).mock
          .calls.length > 0
      );
    });
  });
});
