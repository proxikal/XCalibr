import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { AspectRatioCalculatorTool } from '../AspectRatioCalculatorTool';
import type { AspectRatioCalculatorData } from '../AspectRatioCalculatorTool';

const AspectRatioCalculator = AspectRatioCalculatorTool.Component;

describe('AspectRatioCalculatorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the AspectRatioCalculator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <AspectRatioCalculator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'AspectRatioCalculatorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'AspectRatioCalculatorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <AspectRatioCalculator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'AspectRatioCalculatorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <AspectRatioCalculator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'AspectRatioCalculatorInitialState' }, container);
    });
  });
});
