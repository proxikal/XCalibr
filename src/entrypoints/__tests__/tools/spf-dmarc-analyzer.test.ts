import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('SPF/DMARC Analyzer Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the SPF/DMARC Analyzer interface', async () => {
    const root = await mountWithTool('spfDmarcAnalyzer');
    aiAssertTruthy({ name: 'SpfDmarcAnalyzerRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'SpfDmarcAnalyzerTitle' },
      text.includes('SPF') || text.includes('DMARC') || text.includes('DNS') || text.includes('Domain'));
  });

  it('has domain input', async () => {
    const root = await mountWithTool('spfDmarcAnalyzer');
    const input = root?.querySelector('input');
    aiAssertTruthy({ name: 'SpfDmarcAnalyzerInput' }, input);
  });

  it('has check button', async () => {
    const root = await mountWithTool('spfDmarcAnalyzer');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'SpfDmarcAnalyzerButton' }, button);
  });

  it('shows DNS records area', async () => {
    const root = await mountWithTool('spfDmarcAnalyzer', {
      domain: 'example.com',
      spfRecord: 'v=spf1 include:_spf.google.com ~all',
      dmarcRecord: 'v=DMARC1; p=reject'
    });
    const text = root?.textContent || '';
    const hasRecords = text.includes('SPF') || text.includes('DMARC') || text.includes('v=');
    aiAssertTruthy({ name: 'SpfDmarcAnalyzerRecords' }, hasRecords);
  });
});
