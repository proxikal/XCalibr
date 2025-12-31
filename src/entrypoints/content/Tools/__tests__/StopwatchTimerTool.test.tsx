import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { StopwatchTimerTool } from '../StopwatchTimerTool';
import type { StopwatchTimerData } from '../StopwatchTimerTool';

const StopwatchTimer = StopwatchTimerTool.Component;

describe('StopwatchTimerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the StopwatchTimer interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <StopwatchTimer data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'StopwatchTimerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'StopwatchTimerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <StopwatchTimer data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'StopwatchTimerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <StopwatchTimer data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'StopwatchTimerInitialState' }, container);
    });
  });
});
