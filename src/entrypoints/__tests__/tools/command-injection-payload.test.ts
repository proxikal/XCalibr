import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Command Injection Payload Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Command Injection Payload interface', async () => {
    const root = await mountWithTool('commandInjectionPayload');
    aiAssertTruthy({ name: 'CommandInjectionPayloadRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'CommandInjectionPayloadTitle' },
      text.includes('Command') || text.includes('Injection') || text.includes('Payload') || text.includes('OS'));
  });

  it('shows payload category selector', async () => {
    const root = await mountWithTool('commandInjectionPayload');
    const select = root?.querySelector('select');
    const buttons = root?.querySelectorAll('button');
    aiAssertTruthy({ name: 'CommandInjectionPayloadSelector' }, select || (buttons && buttons.length > 0));
  });

  it('shows payload output area', async () => {
    const root = await mountWithTool('commandInjectionPayload');
    const textarea = root?.querySelector('textarea');
    const pre = root?.querySelector('pre');
    const code = root?.querySelector('code');
    aiAssertTruthy({ name: 'CommandInjectionPayloadOutput' }, textarea || pre || code);
  });

  it('displays command injection payloads', async () => {
    const root = await mountWithTool('commandInjectionPayload', {
      category: 'unix',
      selectedPayload: '; cat /etc/passwd'
    });
    const text = root?.textContent || '';
    const hasPayload = text.includes(';') || text.includes('|') || text.includes('cat') || text.includes('command');
    aiAssertTruthy({ name: 'CommandInjectionPayloadContent' }, hasPayload);
  });
});
