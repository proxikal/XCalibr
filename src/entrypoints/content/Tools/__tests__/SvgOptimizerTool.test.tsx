import { beforeEach, describe, it } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  typeInput
} from '../../../__tests__/integration-test-utils';

describe('SvgOptimizerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('optimizes SVG', async () => {
      const root = await mountWithTool('svgOptimizer');
      if (!root) return;
      const textarea = root.querySelector('textarea[placeholder="<svg>...</svg>"]') as HTMLTextAreaElement | null;
      if (!textarea) return;
      typeInput(textarea, '<svg><!--comment--><path /></svg>');
      const button = findButtonByText(root, 'Optimize SVG');
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const output = root.querySelector('textarea[placeholder="Optimized output..."]') as HTMLTextAreaElement | null;
      aiAssertTruthy({ name: 'SvgOptimizerOutput' }, output?.value?.includes('comment') === false);
    });
  });
});
