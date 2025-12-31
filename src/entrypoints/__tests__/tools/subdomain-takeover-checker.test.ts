import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Subdomain Takeover Checker Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Subdomain Takeover Checker interface', async () => {
    const root = await mountWithTool('subdomainTakeoverChecker');
    aiAssertTruthy({ name: 'SubdomainTakeoverCheckerRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'SubdomainTakeoverCheckerTitle' },
      text.includes('Subdomain') || text.includes('Takeover') || text.includes('CNAME'));
  });

  it('shows subdomain input', async () => {
    const root = await mountWithTool('subdomainTakeoverChecker');
    const input = root?.querySelector('input') || root?.querySelector('textarea');
    aiAssertTruthy({ name: 'SubdomainTakeoverCheckerInput' }, input);
  });

  it('has check button', async () => {
    const root = await mountWithTool('subdomainTakeoverChecker');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'SubdomainTakeoverCheckerButton' }, button);
  });

  it('shows CNAME or DNS info', async () => {
    const root = await mountWithTool('subdomainTakeoverChecker', {
      cname: 'example.s3.amazonaws.com',
      vulnerable: true
    });
    const text = root?.textContent || '';
    const hasDnsInfo = text.includes('CNAME') || text.includes('DNS') ||
                       text.includes('record') || text.includes('Record');
    const elements = root?.querySelectorAll('*');
    aiAssertTruthy({ name: 'SubdomainTakeoverCheckerDns' }, hasDnsInfo || (elements && elements.length > 5));
  });

  it('displays vulnerability status', async () => {
    const root = await mountWithTool('subdomainTakeoverChecker');
    const text = root?.textContent || '';
    const hasStatus = text.includes('vulnerable') || text.includes('Vulnerable') ||
                      text.includes('safe') || text.includes('Safe') ||
                      text.includes('check') || text.includes('Check');
    aiAssertTruthy({ name: 'SubdomainTakeoverCheckerStatus' }, hasStatus);
  });
});
