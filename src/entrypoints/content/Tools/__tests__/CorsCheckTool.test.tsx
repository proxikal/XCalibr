import { beforeEach, describe, it } from 'vitest';
import { aiAssertEqual } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitForState,
  setRuntimeHandler
} from '../../../__tests__/integration-test-utils';

describe('CorsCheckTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('runs CORS check', async () => {
      setRuntimeHandler('xcalibr-cors-check', () => ({
        result: { status: 200, acao: '*', acc: null, methods: 'GET', headers: null }
      }));
      const root = await mountWithTool('corsCheck', {
        url: 'https://example.com'
      });
      if (!root) return;
      const runButton = findButtonByText(root, 'Check');
      runButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { result?: { status?: number } }>;
        return toolData.corsCheck?.result?.status === 200;
      });
      const status = (stored?.toolData as Record<string, { result?: { status?: number } }> | undefined)
        ?.corsCheck?.result?.status;
      aiAssertEqual({ name: 'CorsCheckStatus' }, status, 200);
    });
  });
});
