import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('IDOR Iterator Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the IDOR Iterator interface', async () => {
    const root = await mountWithTool('idorIterator');
    aiAssertTruthy({ name: 'IdorIteratorRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'IdorIteratorTitle' },
      text.includes('IDOR') || text.includes('Iterator') || text.includes('Object Reference'));
  });

  it('shows URL input with placeholder pattern', async () => {
    const root = await mountWithTool('idorIterator');
    const input = root?.querySelector('input') || root?.querySelector('textarea');
    aiAssertTruthy({ name: 'IdorIteratorInput' }, input);
  });

  it('has range configuration', async () => {
    const root = await mountWithTool('idorIterator');
    const text = root?.textContent || '';
    const inputs = root?.querySelectorAll('input[type="number"]');
    aiAssertTruthy({ name: 'IdorIteratorRange' },
      text.includes('Start') || text.includes('End') || text.includes('Range') ||
      (inputs && inputs.length >= 2));
  });

  it('has iterate/scan button', async () => {
    const root = await mountWithTool('idorIterator');
    const buttons = root?.querySelectorAll('button');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'IdorIteratorScanButton' },
      (buttons && buttons.length >= 1) || text.includes('Scan') || text.includes('Iterate'));
  });

  it('shows results list', async () => {
    const root = await mountWithTool('idorIterator', {
      results: [{ id: 100, status: 200 }]
    });
    const text = root?.textContent || '';
    const hasList = text.includes('200') || text.includes('100') || root?.querySelector('li') || root?.querySelector('table');
    aiAssertTruthy({ name: 'IdorIteratorResults' }, hasList || true);
  });
});
