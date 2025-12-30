import { beforeEach, describe, it } from 'vitest';
import { aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitForState,
  setRuntimeHandler
} from '../../../__tests__/integration-test-utils';

describe('WebhookTesterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('sends webhook payloads', async () => {
      setRuntimeHandler('xcalibr-http-request', () => ({
        status: 200,
        statusText: 'OK',
        headers: [],
        body: 'received'
      }));
      const root = await mountWithTool('webhookTester', {
        url: 'https://webhook.site/test',
        body: '',
        response: '',
        error: ''
      });
      if (!root) return;
      const button = findButtonByText(root, 'Send Webhook');
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { response?: string }>;
        return (toolData.webhookTester?.response ?? '').includes('received');
      });
      const output = (stored?.toolData as Record<string, { response?: string }> | undefined)
        ?.webhookTester?.response ?? '';
      aiAssertIncludes({ name: 'WebhookTesterOutput' }, output, 'received');
    });
  });
});
