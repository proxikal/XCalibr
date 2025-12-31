import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('CronGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('cronGenerator');
      aiAssertTruthy({ name: 'CronMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CronTitle' }, text, 'Cron Expression Generator');
    });

    it('renders preset buttons', async () => {
      const root = await mountWithTool('cronGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CronEveryMinute' }, text, 'Every minute');
      aiAssertIncludes({ name: 'CronEvery5Min' }, text, 'Every 5 minutes');
      aiAssertIncludes({ name: 'CronEveryHour' }, text, 'Every hour');
    });

    it('renders field labels', async () => {
      const root = await mountWithTool('cronGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CronMinLabel' }, text, 'Min');
      aiAssertIncludes({ name: 'CronHourLabel' }, text, 'Hour');
      aiAssertIncludes({ name: 'CronDayLabel' }, text, 'Day');
      aiAssertIncludes({ name: 'CronMonthLabel' }, text, 'Month');
    });

    it('renders default expression', async () => {
      const root = await mountWithTool('cronGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CronDefaultExpr' }, text, '* * * * *');
    });
  });

  describe('Preset Buttons', () => {
    it('sets Every minute preset', async () => {
      const root = await mountWithTool('cronGenerator');
      const button = findButtonByText(root!, 'Every minute');
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { minute?: string }>;
        return toolData.cronGenerator?.minute === '*';
      });
      aiAssertTruthy({ name: 'CronPresetEveryMin' }, stored);
    });

    it('sets Every 5 minutes preset', async () => {
      const root = await mountWithTool('cronGenerator');
      const button = findButtonByText(root!, 'Every 5 minutes');
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { minute?: string }>;
        return toolData.cronGenerator?.minute === '*/5';
      });
      aiAssertTruthy({ name: 'CronPreset5Min' }, stored);
    });

    it('sets Every day at midnight preset', async () => {
      const root = await mountWithTool('cronGenerator');
      const button = findButtonByText(root!, 'Every day at midnight');
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { minute?: string; hour?: string }>;
        return toolData.cronGenerator?.minute === '0' && toolData.cronGenerator?.hour === '0';
      });
      aiAssertTruthy({ name: 'CronPresetMidnight' }, stored);
    });

    it('sets Every Monday preset', async () => {
      const root = await mountWithTool('cronGenerator');
      const button = findButtonByText(root!, 'Every Monday');
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { dayOfWeek?: string }>;
        return toolData.cronGenerator?.dayOfWeek === '1';
      });
      aiAssertTruthy({ name: 'CronPresetMonday' }, stored);
    });
  });

  describe('Expression Display', () => {
    it('shows generated expression', async () => {
      const root = await mountWithTool('cronGenerator', {
        minute: '0',
        hour: '*/2',
        dayOfMonth: '*',
        month: '*',
        dayOfWeek: '*'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CronExpr2Hours' }, text, '0 */2 * * *');
    });

    it('shows description for expression', async () => {
      const root = await mountWithTool('cronGenerator', {
        minute: '*',
        hour: '*',
        dayOfMonth: '*',
        month: '*',
        dayOfWeek: '*'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CronDescEveryMin' }, text, 'every minute');
    });
  });

  describe('Persistence', () => {
    it('persists cron fields', async () => {
      const root = await mountWithTool('cronGenerator', {
        minute: '30',
        hour: '6',
        dayOfMonth: '1',
        month: '*',
        dayOfWeek: '*'
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { minute?: string; hour?: string }>;
        return toolData.cronGenerator?.minute === '30' && toolData.cronGenerator?.hour === '6';
      });
      aiAssertTruthy({ name: 'CronPersist' }, stored);
    });
  });
});
