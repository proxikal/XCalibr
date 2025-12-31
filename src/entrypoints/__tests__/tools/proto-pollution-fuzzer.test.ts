import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Proto-Pollution Fuzzer Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Proto-Pollution Fuzzer interface', async () => {
    const root = await mountWithTool('protoPollutionFuzzer');
    aiAssertTruthy({ name: 'ProtoPollutionFuzzerRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'ProtoPollutionFuzzerTitle' },
      text.includes('Prototype') || text.includes('Pollution') || text.includes('Proto'));
  });

  it('shows payload input or selector', async () => {
    const root = await mountWithTool('protoPollutionFuzzer');
    const input = root?.querySelector('input') || root?.querySelector('textarea') || root?.querySelector('select');
    aiAssertTruthy({ name: 'ProtoPollutionFuzzerInput' }, input);
  });

  it('has test/scan button', async () => {
    const root = await mountWithTool('protoPollutionFuzzer');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'ProtoPollutionFuzzerButton' }, button);
  });

  it('displays test payloads', async () => {
    const root = await mountWithTool('protoPollutionFuzzer');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'ProtoPollutionFuzzerPayloads' },
      text.includes('__proto__') || text.includes('constructor') || text.includes('payload') || text.includes('Payload'));
  });

  it('shows results area', async () => {
    const root = await mountWithTool('protoPollutionFuzzer', { results: [{ payload: 'test', vulnerable: false }] });
    const text = root?.textContent || '';
    const elements = root?.querySelectorAll('*');
    aiAssertTruthy({ name: 'ProtoPollutionFuzzerResults' }, (elements && elements.length > 5) || text.includes('result'));
  });
});
