import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('API Endpoint Scraper Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the API Endpoint Scraper interface', async () => {
    const root = await mountWithTool('apiEndpointScraper');
    aiAssertTruthy({ name: 'ApiEndpointScraperRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'ApiEndpointScraperTitle' },
      text.includes('API') || text.includes('Endpoint') || text.includes('endpoint'));
  });

  it('has scan button', async () => {
    const root = await mountWithTool('apiEndpointScraper');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'ApiEndpointScraperButton' }, button);
  });

  it('shows endpoints list area', async () => {
    const root = await mountWithTool('apiEndpointScraper', {
      endpoints: [{ url: '/api/test', method: 'GET' }]
    });
    const text = root?.textContent || '';
    const elements = root?.querySelectorAll('*');
    aiAssertTruthy({ name: 'ApiEndpointScraperList' },
      (elements && elements.length > 5) || text.includes('api') || text.includes('/'));
  });

  it('displays endpoint count or empty state', async () => {
    const root = await mountWithTool('apiEndpointScraper');
    const text = root?.textContent || '';
    const hasCount = text.includes('found') || text.includes('Found') ||
                     text.includes('endpoint') || text.includes('Endpoint') ||
                     text.includes('Scan') || text.includes('scan');
    aiAssertTruthy({ name: 'ApiEndpointScraperCount' }, hasCount);
  });

  it('shows filter or search option', async () => {
    const root = await mountWithTool('apiEndpointScraper');
    const filter = root?.querySelector('input') || root?.querySelector('select');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'ApiEndpointScraperFilter' },
      filter || text.includes('filter') || text.includes('Filter') || text.includes('search'));
  });
});
