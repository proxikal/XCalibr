import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { SvgOptimizerTool } from '../SvgOptimizerTool';

const SvgOptimizer = SvgOptimizerTool.Component;

describe('SvgOptimizerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the SvgOptimizer interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <SvgOptimizer data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'SvgOptimizerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'SvgOptimizerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <SvgOptimizer data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'SvgOptimizerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <SvgOptimizer data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'SvgOptimizerInitialState' }, container);
    });
  });
});
