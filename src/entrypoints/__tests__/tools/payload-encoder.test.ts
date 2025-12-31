import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Payload Encoder', () => {
  beforeEach(() => {
    resetChrome();
    document.body.innerHTML = '';
  });

  afterEach(() => {
    document.body.innerHTML = '';
  });

  it('renders correctly', async () => {
    const root = await mountWithTool('payloadEncoder');
    aiAssertTruthy({ name: 'PayloadEncoderRendered' }, root);
  });

  it('displays encoding options', async () => {
    const root = await mountWithTool('payloadEncoder');
    const text = root?.textContent || '';
    aiAssertTruthy(
      { name: 'HasEncodingOptions' },
      text.includes('URL') || text.includes('Base64') || text.includes('Encoding')
    );
  });
});
