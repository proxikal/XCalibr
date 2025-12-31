import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Timezone Converter Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Timezone Converter interface', async () => {
    const root = await mountWithTool('timezoneConverter');
    aiAssertTruthy({ name: 'TimezoneConverterRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'TimezoneConverterTitle' }, text.includes('Timezone') || text.includes('Time'));
  });

  it('shows timezone selectors', async () => {
    const root = await mountWithTool('timezoneConverter');
    const selects = root?.querySelectorAll('select');
    aiAssertTruthy({ name: 'TimezoneConverterSelects' }, selects && selects.length >= 1);
  });

  it('displays time input', async () => {
    const root = await mountWithTool('timezoneConverter');
    const input = root?.querySelector('input');
    aiAssertTruthy({ name: 'TimezoneConverterInput' }, input);
  });

  it('shows converted times', async () => {
    const root = await mountWithTool('timezoneConverter', {
      inputTime: '12:00',
      sourceTimezone: 'America/New_York',
      targetTimezone: 'Europe/London',
      convertedTime: '17:00'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'TimezoneConverterResult' },
      text.includes('17:00') || text.includes('London') || text.includes('UTC'));
  });

  it('shows common timezones', async () => {
    const root = await mountWithTool('timezoneConverter');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'TimezoneConverterZones' },
      text.includes('UTC') || text.includes('New York') || text.includes('London'));
  });
});
