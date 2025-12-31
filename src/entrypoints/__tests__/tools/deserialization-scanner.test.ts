import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Deserialization Scanner', () => {
  beforeEach(() => {
    resetChrome();
    document.body.innerHTML = '';
  });

  afterEach(() => {
    document.body.innerHTML = '';
  });

  it('renders correctly', async () => {
    const root = await mountWithTool('deserializationScanner');
    aiAssertTruthy({ name: 'DeserializationScannerRendered' }, root);
  });

  it('has interactive elements', async () => {
    const root = await mountWithTool('deserializationScanner');
    aiAssertTruthy(
      { name: 'HasInteractiveElements' },
      root?.querySelector('select') || root?.querySelector('button') || root?.querySelector('textarea')
    );
  });
});
