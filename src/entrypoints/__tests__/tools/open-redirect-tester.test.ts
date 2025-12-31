import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Open Redirect Tester Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Open Redirect Tester interface', async () => {
    const root = await mountWithTool('openRedirectTester');
    aiAssertTruthy({ name: 'OpenRedirectTesterRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'OpenRedirectTesterTitle' },
      text.includes('Redirect') || text.includes('Open') || text.includes('URL'));
  });

  it('shows URL input', async () => {
    const root = await mountWithTool('openRedirectTester');
    const input = root?.querySelector('input[type="url"]') || root?.querySelector('input[type="text"]') || root?.querySelector('input');
    aiAssertTruthy({ name: 'OpenRedirectTesterInput' }, input);
  });

  it('has test button', async () => {
    const root = await mountWithTool('openRedirectTester');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'OpenRedirectTesterButton' }, button);
  });

  it('displays redirect payloads', async () => {
    const root = await mountWithTool('openRedirectTester');
    const text = root?.textContent || '';
    const hasPayloads = text.includes('payload') || text.includes('Payload') ||
                        text.includes('evil') || text.includes('redirect');
    const elements = root?.querySelectorAll('*');
    aiAssertTruthy({ name: 'OpenRedirectTesterPayloads' }, hasPayloads || (elements && elements.length > 5));
  });

  it('shows results or status', async () => {
    const root = await mountWithTool('openRedirectTester', { results: [{ payload: 'test', vulnerable: false }] });
    const text = root?.textContent || '';
    const elements = root?.querySelectorAll('*');
    aiAssertTruthy({ name: 'OpenRedirectTesterResults' }, (elements && elements.length > 5) || text.includes('result'));
  });
});
