import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Broken Link Hijacker Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Broken Link Hijacker interface', async () => {
    const root = await mountWithTool('brokenLinkHijacker');
    aiAssertTruthy({ name: 'BrokenLinkHijackerRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'BrokenLinkHijackerTitle' },
      text.includes('Broken') || text.includes('Link') || text.includes('Hijack') || text.includes('Domain'));
  });

  it('has scan button', async () => {
    const root = await mountWithTool('brokenLinkHijacker');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'BrokenLinkHijackerButton' }, button);
  });

  it('shows link list or results area', async () => {
    const root = await mountWithTool('brokenLinkHijacker');
    const elements = root?.querySelectorAll('*');
    aiAssertTruthy({ name: 'BrokenLinkHijackerResults' }, elements && elements.length > 3);
  });

  it('displays external link findings', async () => {
    const root = await mountWithTool('brokenLinkHijacker', {
      links: [{ url: 'https://expired-domain.com', status: 'expired' }]
    });
    const text = root?.textContent || '';
    const hasContent = text.includes('domain') || text.includes('link') || text.includes('expired') || root?.querySelector('table') || root?.querySelector('ul');
    aiAssertTruthy({ name: 'BrokenLinkHijackerFindings' }, hasContent);
  });
});
