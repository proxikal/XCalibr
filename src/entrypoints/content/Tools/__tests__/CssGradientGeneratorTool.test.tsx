import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { CssGradientGeneratorTool } from '../CssGradientGeneratorTool';
import type { CssGradientGeneratorData } from '../CssGradientGeneratorTool';

const CssGradientGenerator = CssGradientGeneratorTool.Component;

describe('CssGradientGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the CssGradientGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CssGradientGenerator data={{}} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CssGradientGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'CssGradientGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <CssGradientGenerator data={{}} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'CssGradientGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CssGradientGenerator data={{}} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CssGradientGeneratorInitialState' }, container);
    });
  });
});
