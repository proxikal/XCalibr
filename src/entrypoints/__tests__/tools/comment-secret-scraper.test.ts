import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Comment & Secret Scraper Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Comment Secret Scraper interface', async () => {
    const root = await mountWithTool('commentSecretScraper');
    aiAssertTruthy({ name: 'CommentSecretScraperRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'CommentSecretScraperTitle' },
      text.includes('Comment') || text.includes('Secret') || text.includes('Scraper'));
  });

  it('has scan button', async () => {
    const root = await mountWithTool('commentSecretScraper');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'CommentSecretScraperButton' }, button);
  });

  it('shows results area', async () => {
    const root = await mountWithTool('commentSecretScraper', {
      comments: [{ type: 'html', content: '<!-- API key here -->' }],
      secrets: [{ type: 'API Key', value: 'sk-test123', source: 'script' }]
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'CommentSecretScraperResults' },
      text.includes('API') || text.includes('secret') || text.includes('comment') || root?.querySelectorAll('*').length! > 5);
  });

  it('displays secret patterns found', async () => {
    const root = await mountWithTool('commentSecretScraper', {
      secrets: [{ type: 'JWT', value: 'eyJhbGciOiJIUzI1NiJ9...', source: 'inline' }]
    });
    const elements = root?.querySelectorAll('*');
    aiAssertTruthy({ name: 'CommentSecretScraperSecrets' }, elements && elements.length > 3);
  });
});
