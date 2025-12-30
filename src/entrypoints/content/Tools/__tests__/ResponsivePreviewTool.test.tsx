import { beforeEach, describe, it, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  waitFor,
  findButtonByText
} from '../../../__tests__/integration-test-utils';

describe('ResponsivePreviewTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('opens responsive preview window', async () => {
      const openSpy = vi.spyOn(window, 'open').mockReturnValue(null);
      const root = await mountWithTool('responsivePreview');
      if (!root) return;
      const button = await waitFor(() => findButtonByText(root, 'Open Preview Window'));
      aiAssertTruthy({ name: 'ResponsivePreviewButton' }, button);
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      aiAssertTruthy({ name: 'ResponsivePreviewOpen' }, openSpy.mock.calls.length > 0);
      openSpy.mockRestore();
    });
  });
});
