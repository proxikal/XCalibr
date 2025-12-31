import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('cURL to Fetch Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the cURL to Fetch interface', async () => {
    const root = await mountWithTool('curlToFetch');
    aiAssertTruthy({ name: 'CurlToFetchRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'CurlToFetchTitle' }, text.includes('cURL') || text.includes('Fetch') || text.includes('curl'));
  });

  it('shows curl input textarea', async () => {
    const root = await mountWithTool('curlToFetch');
    const textarea = root?.querySelector('textarea');
    aiAssertTruthy({ name: 'CurlToFetchInput' }, textarea);
  });

  it('generates JavaScript fetch code', async () => {
    const root = await mountWithTool('curlToFetch', {
      input: 'curl https://api.example.com',
      output: 'fetch("https://api.example.com")'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'CurlToFetchOutput' },
      text.includes('fetch') || text.includes('https'));
  });

  it('has convert button', async () => {
    const root = await mountWithTool('curlToFetch');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'CurlToFetchButton' }, button);
  });

  it('shows output options', async () => {
    const root = await mountWithTool('curlToFetch');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'CurlToFetchOptions' },
      text.includes('JavaScript') || text.includes('async') || text.includes('options'));
  });
});
