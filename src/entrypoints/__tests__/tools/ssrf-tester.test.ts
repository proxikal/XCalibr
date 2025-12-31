import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('SSRF Tester', () => {
  beforeEach(() => {
    resetChrome();
    document.body.innerHTML = '';
  });

  afterEach(() => {
    document.body.innerHTML = '';
  });

  it('renders correctly', async () => {
    const root = await mountWithTool('ssrfTester');
    aiAssertTruthy({ name: 'SsrfTesterRendered' }, root);
  });

  it('displays bypass techniques', async () => {
    const root = await mountWithTool('ssrfTester');
    const text = root?.textContent || '';
    aiAssertTruthy(
      { name: 'HasBypassTechniques' },
      text.includes('Bypass') || text.includes('IP')
    );
  });
});
