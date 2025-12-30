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

describe('LighthouseSnapshotTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('captures lighthouse snapshot metrics', async () => {
      const root = await mountWithTool('lighthouseSnapshot');
      if (!root) return;
      const button = await waitFor(() => findButtonByText(root, 'Capture'));
      aiAssertTruthy({ name: 'LighthouseCapture' }, button);
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const metric = await waitFor(() => queryAllByText(root, 'TTFB')[0]);
      aiAssertTruthy({ name: 'LighthouseMetric' }, metric);
    });
  });
});
