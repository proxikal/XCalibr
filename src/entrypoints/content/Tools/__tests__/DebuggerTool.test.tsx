import { beforeEach, describe, it } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  waitFor,
  queryAllByText
} from '../../../__tests__/integration-test-utils';

describe('DebuggerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('captures debugger errors', async () => {
      const root = await mountWithTool('debuggerTool');
      if (!root) return;
      window.dispatchEvent(new ErrorEvent('error', { message: 'Boom' }));
      await flushPromises();
      const entry = await waitFor(() => queryAllByText(root, 'Boom')[0]);
      aiAssertTruthy({ name: 'DebuggerEntry' }, entry);
    });
  });
});
