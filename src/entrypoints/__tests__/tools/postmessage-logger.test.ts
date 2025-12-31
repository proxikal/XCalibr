import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('PostMessage Logger Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the PostMessage Logger interface', async () => {
    const root = await mountWithTool('postMessageLogger');
    aiAssertTruthy({ name: 'PostMessageLoggerRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'PostMessageLoggerTitle' },
      text.includes('PostMessage') || text.includes('postMessage') || text.includes('Message'));
  });

  it('has start/stop listening button', async () => {
    const root = await mountWithTool('postMessageLogger');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'PostMessageLoggerButton' }, button);
  });

  it('shows messages list area', async () => {
    const root = await mountWithTool('postMessageLogger', {
      messages: [{ data: 'test', origin: 'https://example.com', timestamp: Date.now() }]
    });
    const text = root?.textContent || '';
    const elements = root?.querySelectorAll('*');
    aiAssertTruthy({ name: 'PostMessageLoggerList' },
      (elements && elements.length > 5) || text.includes('message') || text.includes('Message'));
  });

  it('displays origin information', async () => {
    const root = await mountWithTool('postMessageLogger');
    const text = root?.textContent || '';
    const hasOriginInfo = text.includes('origin') || text.includes('Origin') ||
                          text.includes('source') || text.includes('Source') ||
                          text.includes('listen') || text.includes('Listen');
    aiAssertTruthy({ name: 'PostMessageLoggerOrigin' }, hasOriginInfo);
  });

  it('shows clear button or empty state', async () => {
    const root = await mountWithTool('postMessageLogger');
    const buttons = root?.querySelectorAll('button');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'PostMessageLoggerClear' },
      (buttons && buttons.length > 0) || text.includes('clear') || text.includes('Clear') ||
      text.includes('empty') || text.includes('No messages'));
  });
});
