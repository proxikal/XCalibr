import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool, findButtonByText } from '../integration-test-utils';

describe('Unix Timestamp Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Unix Timestamp interface', async () => {
    const root = await mountWithTool('unixTimestamp');
    aiAssertTruthy({ name: 'UnixTimestampRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'UnixTimestampTitle' }, text.includes('Unix') || text.includes('Timestamp'));
  });

  it('shows current timestamp', async () => {
    const root = await mountWithTool('unixTimestamp');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'UnixTimestampCurrent' },
      text.includes('Current') || text.includes('Now') || /\d{10}/.test(text));
  });

  it('has timestamp input', async () => {
    const root = await mountWithTool('unixTimestamp');
    const input = root?.querySelector('input');
    aiAssertTruthy({ name: 'UnixTimestampInput' }, input);
  });

  it('has convert button', async () => {
    const root = await mountWithTool('unixTimestamp');
    const btn = findButtonByText(root!, 'Convert') || findButtonByText(root!, 'Parse');
    aiAssertTruthy({ name: 'UnixTimestampButton' }, btn);
  });

  it('displays converted date', async () => {
    const root = await mountWithTool('unixTimestamp', {
      timestamp: 1609459200,
      humanDate: '2021-01-01T00:00:00.000Z'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'UnixTimestampDate' },
      text.includes('2021') || text.includes('Jan') || text.includes('01'));
  });
});
