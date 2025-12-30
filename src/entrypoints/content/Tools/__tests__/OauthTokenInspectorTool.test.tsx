import { beforeEach, describe, it } from 'vitest';
import { aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('OauthTokenInspectorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('inspects OAuth tokens', async () => {
      const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
        btoa(JSON.stringify({ scope: 'read' })).replace(/=/g, '') +
        '.sig';
      const root = await mountWithTool('oauthTokenInspector', {
        token,
        output: '',
        error: ''
      });
      if (!root) return;
      const button = findButtonByText(root, 'Inspect Token');
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return (toolData.oauthTokenInspector?.output ?? '').includes('scope');
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.oauthTokenInspector?.output ?? '';
      aiAssertIncludes({ name: 'OAuthTokenOutput' }, output, 'scope');
    });
  });
});
