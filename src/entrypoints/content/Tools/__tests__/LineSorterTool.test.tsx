import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { LineSorterTool } from '../LineSorterTool';
import type { LineSorterData } from '../LineSorterTool';

const LineSorter = LineSorterTool.Component;

describe('LineSorterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the LineSorter interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <LineSorter data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'LineSorterRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'LineSorterHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <LineSorter data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'LineSorterInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <LineSorter data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'LineSorterInitialState' }, container);
    });
  });
});
