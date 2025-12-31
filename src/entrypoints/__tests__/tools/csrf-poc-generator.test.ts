import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('CSRF PoC Generator Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the CSRF PoC Generator interface', async () => {
    const root = await mountWithTool('csrfPocGenerator');
    aiAssertTruthy({ name: 'CsrfPocGeneratorRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'CsrfPocGeneratorTitle' },
      text.includes('CSRF') || text.includes('PoC') || text.includes('Form'));
  });

  it('shows form selector or input', async () => {
    const root = await mountWithTool('csrfPocGenerator');
    const input = root?.querySelector('select') || root?.querySelector('input') || root?.querySelector('textarea');
    aiAssertTruthy({ name: 'CsrfPocGeneratorInput' }, input);
  });

  it('has generate button', async () => {
    const root = await mountWithTool('csrfPocGenerator');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'CsrfPocGeneratorButton' }, button);
  });

  it('shows output area for generated PoC', async () => {
    const root = await mountWithTool('csrfPocGenerator', {
      output: '<html><form action="test">...</form></html>'
    });
    const textarea = root?.querySelector('textarea');
    const pre = root?.querySelector('pre');
    const code = root?.querySelector('code');
    aiAssertTruthy({ name: 'CsrfPocGeneratorOutput' }, textarea || pre || code);
  });

  it('displays form fields or action URL', async () => {
    const root = await mountWithTool('csrfPocGenerator');
    const text = root?.textContent || '';
    const hasFormInfo = text.includes('action') || text.includes('Action') ||
                        text.includes('method') || text.includes('Method') ||
                        text.includes('form') || text.includes('Form');
    aiAssertTruthy({ name: 'CsrfPocGeneratorFormInfo' }, hasFormInfo);
  });
});
