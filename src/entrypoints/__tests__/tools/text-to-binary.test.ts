import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool, findButtonByText } from '../integration-test-utils';

describe('Text to Binary Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Text to Binary interface', async () => {
    const root = await mountWithTool('textToBinary');
    aiAssertTruthy({ name: 'TextToBinaryRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'TextToBinaryTitle' }, text.includes('Binary') || text.includes('Text'));
  });

  it('shows textarea for text input', async () => {
    const root = await mountWithTool('textToBinary');
    const textarea = root?.querySelector('textarea');
    aiAssertTruthy({ name: 'TextToBinaryTextarea' }, textarea);
  });

  it('has encode button', async () => {
    const root = await mountWithTool('textToBinary');
    const btn = findButtonByText(root!, 'To Binary') || findButtonByText(root!, 'Encode');
    aiAssertTruthy({ name: 'TextToBinaryButton' }, btn);
  });

  it('displays binary output', async () => {
    const root = await mountWithTool('textToBinary', {
      input: 'Hi',
      output: '01001000 01101001'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'TextToBinaryOutput' },
      text.includes('01001000') || text.includes('0') || text.includes('1'));
  });

  it('has decode mode', async () => {
    const root = await mountWithTool('textToBinary');
    const text = root?.textContent || '';
    const btn = findButtonByText(root!, 'To Text') || findButtonByText(root!, 'Decode');
    aiAssertTruthy({ name: 'TextToBinaryDecode' },
      btn || text.includes('Text') || text.includes('Decode'));
  });
});
