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

describe('ApiResponseViewerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('fetches API response', async () => {
      setRuntimeHandler('xcalibr-http-request', () => ({
        status: 200,
        statusText: 'OK',
        headers: [],
        body: 'ok'
      }));
      const root = await mountWithTool('apiResponseViewer', {
        url: 'https://api.example.com',
        response: '',
        status: '',
        error: ''
      });
      if (!root) return;
      const button = findButtonByText(root, 'Fetch Response');
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { response?: string }>;
        return (toolData.apiResponseViewer?.response ?? '').includes('ok');
      });
      const output = (stored?.toolData as Record<string, { response?: string }> | undefined)
        ?.apiResponseViewer?.response ?? '';
      aiAssertIncludes({ name: 'ApiResponseViewerOutput' }, output, 'ok');
    });
  });
});
