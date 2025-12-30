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

describe('RestClientTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('sends REST requests', async () => {
      setRuntimeHandler('xcalibr-http-request', () => ({
        status: 200,
        statusText: 'OK',
        headers: [],
        body: 'pong'
      }));
      const root = await mountWithTool('restClient', {
        url: 'https://api.example.com',
        method: 'GET',
        headers: '',
        body: '',
        response: '',
        error: ''
      });
      if (!root) return;
      const button = findButtonByText(root, 'Send Request');
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { response?: string }>;
        return (toolData.restClient?.response ?? '').includes('pong');
      });
      const output = (stored?.toolData as Record<string, { response?: string }> | undefined)
        ?.restClient?.response ?? '';
      aiAssertIncludes({ name: 'RestClientOutput' }, output, 'pong');
    });
  });
});
