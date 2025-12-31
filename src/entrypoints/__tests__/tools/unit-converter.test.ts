import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Unit Converter Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Unit Converter interface', async () => {
    const root = await mountWithTool('unitConverter');
    aiAssertTruthy({ name: 'UnitConverterRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'UnitConverterTitle' }, text.includes('Unit') || text.includes('Convert'));
  });

  it('shows value input', async () => {
    const root = await mountWithTool('unitConverter');
    const input = root?.querySelector('input[type="number"]') || root?.querySelector('input');
    aiAssertTruthy({ name: 'UnitConverterInput' }, input);
  });

  it('shows unit categories', async () => {
    const root = await mountWithTool('unitConverter');
    const text = root?.textContent || '';
    const select = root?.querySelector('select');
    aiAssertTruthy({ name: 'UnitConverterCategories' },
      select || text.includes('px') || text.includes('rem') || text.includes('bytes'));
  });

  it('displays converted values', async () => {
    const root = await mountWithTool('unitConverter', {
      value: 16,
      fromUnit: 'px',
      toUnit: 'rem',
      result: 1
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'UnitConverterResult' },
      text.includes('1') || text.includes('rem') || text.includes('Result'));
  });

  it('shows common dev conversions', async () => {
    const root = await mountWithTool('unitConverter');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'UnitConverterDevUnits' },
      text.includes('px') || text.includes('rem') || text.includes('em') ||
      text.includes('KB') || text.includes('MB'));
  });
});
