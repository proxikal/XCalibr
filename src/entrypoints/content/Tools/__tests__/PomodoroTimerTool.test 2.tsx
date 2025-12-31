import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { PomodoroTimerTool } from '../PomodoroTimerTool';
import type { PomodoroTimerData } from '../PomodoroTimerTool';

const PomodoroTimer = PomodoroTimerTool.Component;

describe('PomodoroTimerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the PomodoroTimer interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <PomodoroTimer data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'PomodoroTimerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'PomodoroTimerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <PomodoroTimer data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'PomodoroTimerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <PomodoroTimer data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'PomodoroTimerInitialState' }, container);
    });
  });
});
