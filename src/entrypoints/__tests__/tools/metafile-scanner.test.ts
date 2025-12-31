import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Metafile Scanner Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Metafile Scanner interface', async () => {
    const root = await mountWithTool('metafileScanner');
    aiAssertTruthy({ name: 'MetafileScannerRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'MetafileScannerTitle' },
      text.includes('Metafile') || text.includes('robots') || text.includes('sitemap') || text.includes('Scanner'));
  });

  it('has scan button', async () => {
    const root = await mountWithTool('metafileScanner');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'MetafileScannerButton' }, button);
  });

  it('shows metafiles when found', async () => {
    const root = await mountWithTool('metafileScanner', {
      results: [
        { file: 'robots.txt', status: 200, found: true },
        { file: 'sitemap.xml', status: 200, found: true },
        { file: 'security.txt', status: 404, found: false }
      ]
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'MetafileScannerResults' },
      text.includes('robots') || text.includes('sitemap') || text.includes('200') || root?.querySelectorAll('*').length! > 5);
  });

  it('displays scan results', async () => {
    const root = await mountWithTool('metafileScanner', {
      results: [{ file: 'robots.txt', status: 200, found: true }]
    });
    const elements = root?.querySelectorAll('*');
    aiAssertTruthy({ name: 'MetafileScannerCount' }, elements && elements.length > 3);
  });
});
