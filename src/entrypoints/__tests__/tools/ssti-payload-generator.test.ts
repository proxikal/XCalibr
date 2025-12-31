import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('SSTI Payload Generator', () => {
  beforeEach(() => {
    resetChrome();
    document.body.innerHTML = '';
  });

  afterEach(() => {
    document.body.innerHTML = '';
  });

  it('renders correctly', async () => {
    const root = await mountWithTool('sstiPayloadGenerator');
    aiAssertTruthy({ name: 'SstiPayloadGeneratorRendered' }, root);
  });

  it('displays template engine categories', async () => {
    const root = await mountWithTool('sstiPayloadGenerator');
    const text = root?.textContent || '';
    aiAssertTruthy(
      { name: 'HasTemplateEngineCategories' },
      text.includes('Jinja2') || text.includes('Template Engine')
    );
  });

  it('shows payload categories', async () => {
    const root = await mountWithTool('sstiPayloadGenerator');
    const text = root?.textContent || '';
    aiAssertTruthy(
      { name: 'HasPayloadCategories' },
      text.includes('Detection') || text.includes('RCE') || text.includes('Bypass')
    );
  });
});
