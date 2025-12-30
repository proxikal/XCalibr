import { beforeEach, describe, it } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('FontIdentifierTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('identifies fonts', async () => {
      const fontTarget = document.createElement('div');
      fontTarget.className = 'font-target';
      fontTarget.style.fontFamily = 'Arial';
      fontTarget.style.fontSize = '16px';
      fontTarget.style.fontWeight = '400';
      fontTarget.style.lineHeight = '1.5';
      document.body.appendChild(fontTarget);

      const root = await mountWithTool('fontIdentifier', {
        isActive: false,
        history: []
      });
      if (!root) return;

      const activateButton = findButtonByText(root, 'Activate Picker');
      aiAssertTruthy({ name: 'FontIdentifierActivateButton' }, activateButton);
      activateButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();

      fontTarget.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();

      type FontEntry = { fontFamily: string };
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { history?: FontEntry[] }>;
        return (toolData.fontIdentifier?.history ?? []).length > 0;
      });
      const history = (stored?.toolData as Record<string, { history?: FontEntry[] }> | undefined)
        ?.fontIdentifier?.history ?? [];
      aiAssertTruthy({ name: 'FontIdentifierHistory', state: history }, history.length > 0);
      aiAssertTruthy(
        { name: 'FontIdentifierFontFamily', state: history },
        history[0]?.fontFamily?.includes('Arial')
      );

      fontTarget.remove();
    });
  });
});
