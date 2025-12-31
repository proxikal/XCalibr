import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Unicode Explorer Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Unicode Explorer interface', async () => {
    const root = await mountWithTool('unicodeExplorer');
    aiAssertTruthy({ name: 'UnicodeExplorerRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'UnicodeExplorerTitle' }, text.includes('Unicode') || text.includes('Character'));
  });

  it('shows search input', async () => {
    const root = await mountWithTool('unicodeExplorer');
    const input = root?.querySelector('input');
    aiAssertTruthy({ name: 'UnicodeExplorerSearch' }, input);
  });

  it('displays character grid or list', async () => {
    const root = await mountWithTool('unicodeExplorer');
    const gridItems = root?.querySelectorAll('button') || root?.querySelectorAll('div');
    aiAssertTruthy({ name: 'UnicodeExplorerGrid' }, gridItems && gridItems.length > 0);
  });

  it('shows character details when selected', async () => {
    const root = await mountWithTool('unicodeExplorer', {
      selectedChar: 'A',
      charCode: 65
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'UnicodeExplorerDetails' },
      text.includes('65') || text.includes('A') || text.includes('U+'));
  });

  it('shows category filter', async () => {
    const root = await mountWithTool('unicodeExplorer');
    const select = root?.querySelector('select');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'UnicodeExplorerCategory' },
      select || text.includes('Emoji') || text.includes('Symbol') || text.includes('Arrow'));
  });
});
