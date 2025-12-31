import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool, findButtonByText } from '../integration-test-utils';

describe('String Obfuscator Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the String Obfuscator interface', async () => {
    const root = await mountWithTool('stringObfuscator');
    aiAssertTruthy({ name: 'StringObfuscatorRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'StringObfuscatorTitle' }, text.includes('Obfuscator') || text.includes('String'));
  });

  it('shows textarea for string input', async () => {
    const root = await mountWithTool('stringObfuscator');
    const input = root?.querySelector('textarea') || root?.querySelector('input');
    aiAssertTruthy({ name: 'StringObfuscatorInput' }, input);
  });

  it('has obfuscate button', async () => {
    const root = await mountWithTool('stringObfuscator');
    const btn = findButtonByText(root!, 'Obfuscate');
    aiAssertTruthy({ name: 'StringObfuscatorButton' }, btn);
  });

  it('displays obfuscated output', async () => {
    const root = await mountWithTool('stringObfuscator', {
      input: 'hello',
      output: '\\x68\\x65\\x6c\\x6c\\x6f'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'StringObfuscatorOutput' },
      text.includes('\\x') || text.includes('0x') || text.includes('Output'));
  });

  it('shows obfuscation method options', async () => {
    const root = await mountWithTool('stringObfuscator');
    const select = root?.querySelector('select');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'StringObfuscatorMethods' },
      select || text.includes('Hex') || text.includes('Unicode'));
  });
});
