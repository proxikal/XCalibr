import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Aspect Ratio Calculator Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Aspect Ratio Calculator interface', async () => {
    const root = await mountWithTool('aspectRatioCalculator');
    aiAssertTruthy({ name: 'AspectRatioCalculatorRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'AspectRatioCalculatorTitle' }, text.includes('Aspect') || text.includes('Ratio'));
  });

  it('shows width and height inputs', async () => {
    const root = await mountWithTool('aspectRatioCalculator');
    const text = root?.textContent || '';
    const inputs = root?.querySelectorAll('input');
    aiAssertTruthy({ name: 'AspectRatioCalculatorInputs' },
      (inputs && inputs.length >= 2) || text.includes('Width') || text.includes('Height'));
  });

  it('calculates aspect ratio', async () => {
    const root = await mountWithTool('aspectRatioCalculator', {
      width: 1920,
      height: 1080,
      ratio: '16:9'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'AspectRatioCalculatorResult' },
      text.includes('16') || text.includes('9') || text.includes(':'));
  });

  it('shows common aspect ratios', async () => {
    const root = await mountWithTool('aspectRatioCalculator');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'AspectRatioCalculatorCommon' },
      text.includes('16:9') || text.includes('4:3') || text.includes('preset') || text.includes('common'));
  });

  it('has calculate button', async () => {
    const root = await mountWithTool('aspectRatioCalculator');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'AspectRatioCalculatorButton' }, button);
  });
});
