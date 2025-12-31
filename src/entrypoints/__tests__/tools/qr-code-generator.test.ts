import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('QR Code Generator Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the QR Code Generator interface', async () => {
    const root = await mountWithTool('qrCodeGenerator');
    aiAssertTruthy({ name: 'QrCodeGeneratorRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'QrCodeGeneratorTitle' }, text.includes('QR') || text.includes('Code'));
  });

  it('shows text input', async () => {
    const root = await mountWithTool('qrCodeGenerator');
    const input = root?.querySelector('input') || root?.querySelector('textarea');
    aiAssertTruthy({ name: 'QrCodeGeneratorInput' }, input);
  });

  it('has generate button', async () => {
    const root = await mountWithTool('qrCodeGenerator');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'QrCodeGeneratorButton' }, button);
  });

  it('shows color options', async () => {
    const root = await mountWithTool('qrCodeGenerator');
    const text = root?.textContent || '';
    const colorInput = root?.querySelector('input[type="color"]');
    aiAssertTruthy({ name: 'QrCodeGeneratorColors' },
      colorInput || text.includes('color') || text.includes('Color'));
  });

  it('shows size options', async () => {
    const root = await mountWithTool('qrCodeGenerator');
    const text = root?.textContent || '';
    const numberInput = root?.querySelector('input[type="number"]') || root?.querySelector('select');
    aiAssertTruthy({ name: 'QrCodeGeneratorSize' },
      numberInput || text.includes('size') || text.includes('Size'));
  });
});
