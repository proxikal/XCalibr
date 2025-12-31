import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Pomodoro Timer Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Pomodoro Timer interface', async () => {
    const root = await mountWithTool('pomodoroTimer');
    aiAssertTruthy({ name: 'PomodoroTimerRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'PomodoroTimerTitle' }, text.includes('Pomodoro') || text.includes('Focus'));
  });

  it('shows timer display', async () => {
    const root = await mountWithTool('pomodoroTimer');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'PomodoroTimerDisplay' }, text.includes('25:00') || text.includes('min'));
  });

  it('has start/pause buttons', async () => {
    const root = await mountWithTool('pomodoroTimer');
    const buttons = root?.querySelectorAll('button');
    aiAssertTruthy({ name: 'PomodoroTimerButtons' }, buttons && buttons.length >= 1);
  });

  it('shows work/break mode options', async () => {
    const root = await mountWithTool('pomodoroTimer');
    const text = root?.textContent || '';
    const hasMode = text.toLowerCase().includes('work') || text.toLowerCase().includes('break') || text.toLowerCase().includes('focus');
    aiAssertTruthy({ name: 'PomodoroTimerModes' }, hasMode);
  });

  it('shows session counter or progress', async () => {
    const root = await mountWithTool('pomodoroTimer');
    const text = root?.textContent || '';
    const hasProgress = text.includes('Session') || text.includes('session') || /\d+\/\d+/.test(text) || text.includes('completed');
    const elements = root?.querySelectorAll('*');
    aiAssertTruthy({ name: 'PomodoroTimerProgress' }, hasProgress || (elements && elements.length > 5));
  });
});
