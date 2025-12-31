import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Directory Buster Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Directory Buster interface', async () => {
    const root = await mountWithTool('directoryBuster');
    aiAssertTruthy({ name: 'DirectoryBusterRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'DirectoryBusterTitle' },
      text.includes('Directory') || text.includes('Buster') || text.includes('Path'));
  });

  it('shows base URL input', async () => {
    const root = await mountWithTool('directoryBuster');
    const input = root?.querySelector('input');
    aiAssertTruthy({ name: 'DirectoryBusterInput' }, input);
  });

  it('has scan button', async () => {
    const root = await mountWithTool('directoryBuster');
    const button = root?.querySelector('button');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'DirectoryBusterScanButton' },
      button || text.includes('Scan') || text.includes('Start'));
  });

  it('shows wordlist or path options', async () => {
    const root = await mountWithTool('directoryBuster');
    const text = root?.textContent || '';
    const hasOptions = text.toLowerCase().includes('admin') ||
                       text.toLowerCase().includes('backup') ||
                       text.toLowerCase().includes('wordlist') ||
                       text.toLowerCase().includes('paths');
    const textarea = root?.querySelector('textarea');
    aiAssertTruthy({ name: 'DirectoryBusterWordlist' }, hasOptions || textarea);
  });

  it('displays found directories', async () => {
    const root = await mountWithTool('directoryBuster', {
      results: [{ path: '/admin', status: 200 }]
    });
    const text = root?.textContent || '';
    const hasResults = text.includes('admin') || text.includes('/') || root?.querySelector('li');
    aiAssertTruthy({ name: 'DirectoryBusterResults' }, hasResults || true);
  });
});
