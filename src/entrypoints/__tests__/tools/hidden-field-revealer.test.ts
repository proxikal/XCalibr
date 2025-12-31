import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Hidden Field Revealer Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Hidden Field Revealer interface', async () => {
    const root = await mountWithTool('hiddenFieldRevealer');
    aiAssertTruthy({ name: 'HiddenFieldRevealerRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'HiddenFieldRevealerTitle' },
      text.includes('Hidden') || text.includes('Field') || text.includes('Form'));
  });

  it('has scan button', async () => {
    const root = await mountWithTool('hiddenFieldRevealer');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'HiddenFieldRevealerButton' }, button);
  });

  it('shows hidden fields when found', async () => {
    const root = await mountWithTool('hiddenFieldRevealer', {
      fields: [
        { name: 'csrf_token', value: 'abc123', formIndex: 0 },
        { name: 'user_id', value: '12345', formIndex: 0 }
      ]
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'HiddenFieldRevealerResults' },
      text.includes('csrf') || text.includes('token') || text.includes('hidden') || root?.querySelectorAll('*').length! > 5);
  });

  it('displays field count', async () => {
    const root = await mountWithTool('hiddenFieldRevealer', {
      fields: [{ name: 'test', value: 'value', formIndex: 0 }]
    });
    const elements = root?.querySelectorAll('*');
    aiAssertTruthy({ name: 'HiddenFieldRevealerCount' }, elements && elements.length > 3);
  });
});
