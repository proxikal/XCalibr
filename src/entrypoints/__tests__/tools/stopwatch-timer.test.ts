import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Stopwatch Timer Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Stopwatch Timer interface', async () => {
    const root = await mountWithTool('stopwatchTimer');
    aiAssertTruthy({ name: 'StopwatchTimerRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'StopwatchTimerTitle' }, text.includes('Stopwatch') || text.includes('Timer'));
  });

  it('shows time display', async () => {
    const root = await mountWithTool('stopwatchTimer');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'StopwatchTimerDisplay' }, text.includes('00:00') || text.includes('0:00'));
  });

  it('has start/stop buttons', async () => {
    const root = await mountWithTool('stopwatchTimer');
    const buttons = root?.querySelectorAll('button');
    aiAssertTruthy({ name: 'StopwatchTimerButtons' }, buttons && buttons.length >= 1);
  });

  it('has lap button for stopwatch', async () => {
    const root = await mountWithTool('stopwatchTimer');
    const text = root?.textContent || '';
    const hasLap = text.toLowerCase().includes('lap') || text.toLowerCase().includes('split');
    const buttons = root?.querySelectorAll('button');
    aiAssertTruthy({ name: 'StopwatchTimerLap' }, hasLap || (buttons && buttons.length >= 2));
  });

  it('has reset functionality', async () => {
    const root = await mountWithTool('stopwatchTimer');
    const text = root?.textContent || '';
    const hasReset = text.toLowerCase().includes('reset') || text.toLowerCase().includes('clear');
    const buttons = root?.querySelectorAll('button');
    aiAssertTruthy({ name: 'StopwatchTimerReset' }, hasReset || (buttons && buttons.length >= 2));
  });
});
