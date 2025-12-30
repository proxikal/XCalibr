import { beforeEach, describe, it } from 'vitest';
import { aiAssertIncludes, aiAssertTruthy } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  waitFor,
  findButtonByText,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('UrlCodecTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('encodes input in URL Encoder/Decoder', async () => {
      const root = await mountWithTool('urlCodec', {
        input: 'hello world',
        output: '',
        mode: 'decode'
      });
      if (!root) return;
      const toggleButton = await waitFor(() => findButtonByText(root, 'Decode'));
      aiAssertTruthy({ name: 'UrlCodecToggleButton' }, toggleButton);
      toggleButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return (toolData.urlCodec?.output ?? '').includes('hello%20world');
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.urlCodec?.output ?? '';
      aiAssertIncludes(
        { name: 'UrlCodecOutput', input: { text: 'hello world' } },
        output,
        'hello%20world'
      );
    });
  });
});
