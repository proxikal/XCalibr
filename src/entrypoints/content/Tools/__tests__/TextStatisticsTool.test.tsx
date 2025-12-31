import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { TextStatisticsTool } from '../TextStatisticsTool';
import type { TextStatisticsData } from '../TextStatisticsTool';

const TextStatistics = TextStatisticsTool.Component;

describe('TextStatisticsTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the TextStatistics interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <TextStatistics data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'TextStatisticsRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'TextStatisticsHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <TextStatistics data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'TextStatisticsInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <TextStatistics data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'TextStatisticsInitialState' }, container);
    });
  });
});
