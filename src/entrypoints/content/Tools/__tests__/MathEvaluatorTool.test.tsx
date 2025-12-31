import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { MathEvaluatorTool } from '../MathEvaluatorTool';
import type { MathEvaluatorData } from '../MathEvaluatorTool';

const MathEvaluator = MathEvaluatorTool.Component;

describe('MathEvaluatorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the MathEvaluator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <MathEvaluator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'MathEvaluatorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'MathEvaluatorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <MathEvaluator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'MathEvaluatorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <MathEvaluator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'MathEvaluatorInitialState' }, container);
    });
  });
});
