import { beforeEach, describe, it } from 'vitest';
import { aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('JwtDebuggerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('decodes JWT in debugger tools', async () => {
      const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
        btoa(JSON.stringify({ sub: '123' })).replace(/=/g, '') +
        '.sig';
      const root = await mountWithTool('jwtDebugger', {
        token,
        output: '',
        error: ''
      });
      if (!root) return;
      const button = findButtonByText(root, 'Decode Token');
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { payload?: string }>;
        return (toolData.jwtDebugger?.payload ?? '').includes('sub');
      });
      const payload = (stored?.toolData as Record<string, { payload?: string }> | undefined)
        ?.jwtDebugger?.payload ?? '';
      aiAssertIncludes({ name: 'JwtDebuggerPayload' }, payload, 'sub');
    });
  });
});
