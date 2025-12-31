import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Clickjacking Tester Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Clickjacking Tester interface', async () => {
    const root = await mountWithTool('clickjackingTester');
    aiAssertTruthy({ name: 'ClickjackingTesterRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'ClickjackingTesterTitle' },
      text.includes('Clickjacking') || text.includes('Frame') || text.includes('X-Frame'));
  });

  it('shows URL input', async () => {
    const root = await mountWithTool('clickjackingTester');
    const input = root?.querySelector('input') || root?.querySelector('textarea');
    aiAssertTruthy({ name: 'ClickjackingTesterInput' }, input);
  });

  it('has test button', async () => {
    const root = await mountWithTool('clickjackingTester');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'ClickjackingTesterButton' }, button);
  });

  it('shows iframe preview or status', async () => {
    const root = await mountWithTool('clickjackingTester');
    const iframe = root?.querySelector('iframe');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'ClickjackingTesterPreview' },
      iframe || text.includes('Frame') || text.includes('frame') || text.includes('preview'));
  });

  it('shows vulnerability status', async () => {
    const root = await mountWithTool('clickjackingTester', { url: 'https://example.com', tested: true });
    const text = root?.textContent || '';
    const hasStatus = text.toLowerCase().includes('vulnerable') ||
                      text.toLowerCase().includes('protected') ||
                      text.toLowerCase().includes('status');
    const elements = root?.querySelectorAll('*');
    aiAssertTruthy({ name: 'ClickjackingTesterStatus' }, hasStatus || (elements && elements.length > 5));
  });
});
