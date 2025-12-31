import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('XXE Payload Generator Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the XXE Payload Generator interface', async () => {
    const root = await mountWithTool('xxePayloadGenerator');
    aiAssertTruthy({ name: 'XxePayloadGeneratorRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'XxePayloadGeneratorTitle' },
      text.includes('XXE') || text.includes('XML') || text.includes('Payload') || text.includes('Entity'));
  });

  it('shows payload type selector or list', async () => {
    const root = await mountWithTool('xxePayloadGenerator');
    const select = root?.querySelector('select');
    const buttons = root?.querySelectorAll('button');
    aiAssertTruthy({ name: 'XxePayloadGeneratorSelector' }, select || (buttons && buttons.length > 0));
  });

  it('shows payload output area', async () => {
    const root = await mountWithTool('xxePayloadGenerator');
    const textarea = root?.querySelector('textarea');
    const pre = root?.querySelector('pre');
    const code = root?.querySelector('code');
    aiAssertTruthy({ name: 'XxePayloadGeneratorOutput' }, textarea || pre || code);
  });

  it('displays XXE payload content', async () => {
    const root = await mountWithTool('xxePayloadGenerator', {
      selectedPayload: 'basic',
      output: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    });
    const text = root?.textContent || '';
    const hasPayload = text.includes('DOCTYPE') || text.includes('ENTITY') || text.includes('xml') || text.includes('XXE');
    aiAssertTruthy({ name: 'XxePayloadGeneratorContent' }, hasPayload);
  });
});
