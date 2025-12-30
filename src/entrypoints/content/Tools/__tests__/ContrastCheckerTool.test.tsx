import { beforeEach, describe, it } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  queryAllByText
} from '../../../__tests__/integration-test-utils';

describe('ContrastCheckerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('checks contrast ratio', async () => {
      const root = await mountWithTool('contrastChecker');
      if (!root) return;
      const button = findButtonByText(root, 'Check Contrast');
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const ratio = queryAllByText(root, 'Ratio:')[0];
      aiAssertTruthy({ name: 'ContrastRatio' }, ratio);
    });
  });
});
