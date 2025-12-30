import { beforeEach, describe, it } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitFor,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('AnimationPreviewTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('updates animation preview styles', async () => {
      const root = await mountWithTool('animationPreview', {
        css: 'animation: pulse 2s linear infinite;'
      });
      if (!root) return;
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { css?: string }>;
        return (toolData.animationPreview?.css ?? '').includes('pulse 2s');
      });
      const styleTag = await waitFor(() =>
        Array.from(root.querySelectorAll('style')).find((node) =>
          node.textContent?.includes('pulse 2s')
        )
      );
      aiAssertTruthy(
        { name: 'AnimationPreviewStyle', state: stored?.toolData },
        styleTag
      );
    });
  });
});
