import { beforeEach, describe, it } from 'vitest';
import { aiAssertEqual, aiAssertTruthy } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  flushPromises,
  waitFor,
  findButtonByText,
  getState,
  setState,
  mountContent,
  getShadowRoot
} from '../../../__tests__/integration-test-utils';

describe('JsonMinifierTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('minifies JSON in the JSON Minifier tool', async () => {
      await setState({
        isOpen: true,
        isVisible: true,
        toolWindows: {
          jsonMinifier: { isOpen: true, isMinimized: false, x: 80, y: 120 }
        },
        toolData: {
          jsonMinifier: { input: '{"a": 1}', output: '', error: '' }
        }
      });
      await mountContent();
      const root = getShadowRoot();
      if (!root) return;

      const input = (await waitFor(() =>
        root.querySelector('textarea[placeholder="Paste JSON here..."]')
      )) as HTMLTextAreaElement | null;
      aiAssertTruthy({ name: 'JsonMinifierInput' }, input);
      if (!input) return;
      aiAssertEqual(
        { name: 'JsonMinifierInputValue' },
        input.value,
        '{"a": 1}'
      );

      const minifyButton = findButtonByText(root, 'Minify');
      minifyButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();

      const storedAfter = await getState();
      const toolDataAfter = storedAfter.toolData as Record<
        string,
        { output?: string }
      >;
      aiAssertEqual(
        { name: 'JsonMinifierOutput', input: { raw: '{"a": 1}' } },
        toolDataAfter.jsonMinifier?.output ?? '',
        '{"a":1}'
      );
    });
  });
});
