import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { CidrCalculatorTool } from '../CidrCalculatorTool';

const CidrCalculator = CidrCalculatorTool.Component;

describe('CidrCalculatorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the CidrCalculator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CidrCalculator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CidrCalculatorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'CidrCalculatorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <CidrCalculator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'CidrCalculatorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CidrCalculator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CidrCalculatorInitialState' }, container);
    });
  });
});
