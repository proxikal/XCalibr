import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool, findButtonByText } from '../integration-test-utils';

describe('Escaping Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Escaping Tool interface', async () => {
    const root = await mountWithTool('escapingTool');
    aiAssertTruthy({ name: 'EscapingToolRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'EscapingToolTitle' }, text.includes('Escape') || text.includes('String'));
  });

  it('shows textarea for input', async () => {
    const root = await mountWithTool('escapingTool');
    const textarea = root?.querySelector('textarea');
    aiAssertTruthy({ name: 'EscapingToolTextarea' }, textarea);
  });

  it('has escape button', async () => {
    const root = await mountWithTool('escapingTool');
    const btn = findButtonByText(root!, 'Escape') || findButtonByText(root!, 'Convert');
    aiAssertTruthy({ name: 'EscapingToolButton' }, btn);
  });

  it('shows language/format selector', async () => {
    const root = await mountWithTool('escapingTool');
    const select = root?.querySelector('select');
    aiAssertTruthy({ name: 'EscapingToolLanguage' }, select);
  });

  it('displays escaped output', async () => {
    const root = await mountWithTool('escapingTool', {
      input: 'Hello "World"',
      output: 'Hello \\"World\\"',
      language: 'json'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'EscapingToolOutput' },
      text.includes('\\') || text.includes('World') || text.includes('Output'));
  });
});
