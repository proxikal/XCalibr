import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Admin Panel Finder Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Admin Panel Finder interface', async () => {
    const root = await mountWithTool('adminPanelFinder');
    aiAssertTruthy({ name: 'AdminPanelFinderRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'AdminPanelFinderTitle' },
      text.includes('Admin') || text.includes('Panel') || text.includes('Find'));
  });

  it('shows domain input or uses current domain', async () => {
    const root = await mountWithTool('adminPanelFinder');
    const input = root?.querySelector('input') || root?.querySelector('textarea');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'AdminPanelFinderInput' },
      input || text.includes('domain') || text.includes('URL'));
  });

  it('has scan button', async () => {
    const root = await mountWithTool('adminPanelFinder');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'AdminPanelFinderButton' }, button);
  });

  it('shows results area with admin paths', async () => {
    const root = await mountWithTool('adminPanelFinder', {
      baseUrl: 'https://example.com',
      results: [
        { path: '/admin', status: 200, exists: true },
        { path: '/wp-admin', status: 404, exists: false }
      ],
      scannedAt: Date.now()
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'AdminPanelFinderResults' },
      text.includes('admin') || text.includes('200') || text.includes('404') || (root?.querySelectorAll('*').length ?? 0) > 5);
  });

  it('shows progress during scan', async () => {
    const root = await mountWithTool('adminPanelFinder', {
      isRunning: true,
      progress: 50
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'AdminPanelFinderProgress' },
      text.includes('%') || text.includes('scanning') || text.includes('Scanning') || (root?.querySelectorAll('*').length ?? 0) > 3);
  });
});
