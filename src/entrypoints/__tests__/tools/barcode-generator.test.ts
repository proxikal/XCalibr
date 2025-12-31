import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Barcode Generator Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Barcode Generator interface', async () => {
    const root = await mountWithTool('barcodeGenerator');
    aiAssertTruthy({ name: 'BarcodeGeneratorRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'BarcodeGeneratorTitle' }, text.includes('Barcode') || text.includes('barcode'));
  });

  it('shows text input', async () => {
    const root = await mountWithTool('barcodeGenerator');
    const input = root?.querySelector('input') || root?.querySelector('textarea');
    aiAssertTruthy({ name: 'BarcodeGeneratorInput' }, input);
  });

  it('has generate button', async () => {
    const root = await mountWithTool('barcodeGenerator');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'BarcodeGeneratorButton' }, button);
  });

  it('shows barcode format options', async () => {
    const root = await mountWithTool('barcodeGenerator');
    const text = root?.textContent || '';
    const select = root?.querySelector('select');
    aiAssertTruthy({ name: 'BarcodeGeneratorFormats' },
      select || text.includes('CODE128') || text.includes('UPC') || text.includes('EAN'));
  });

  it('displays generated barcode', async () => {
    const root = await mountWithTool('barcodeGenerator', {
      text: '12345',
      format: 'CODE128'
    });
    const canvas = root?.querySelector('canvas');
    const svg = root?.querySelector('svg');
    const img = root?.querySelector('img');
    aiAssertTruthy({ name: 'BarcodeGeneratorOutput' }, canvas || svg || img);
  });
});
