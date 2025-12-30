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

describe('PayloadReplayTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('replays payloads with Payload Replay', async () => {
      setRuntimeHandler('xcalibr-payload-replay', () => ({
        responseStatus: 200,
        responseHeaders: [],
        responseBody: 'ok'
      }));
      const root = await mountWithTool('payloadReplay', {
        url: 'https://example.com/api',
        method: 'GET',
        headers: '',
        body: ''
      });
      if (!root) return;
      const sendButton = findButtonByText(root, 'Send Request');
      sendButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { responseBody?: string }>;
        return (toolData.payloadReplay?.responseBody ?? '').includes('ok');
      });
      const output = (stored?.toolData as Record<string, { responseBody?: string }> | undefined)
        ?.payloadReplay?.responseBody ?? '';
      aiAssertIncludes(
        { name: 'PayloadReplayOutput' },
        output,
        'ok'
      );
    });
  });
});
