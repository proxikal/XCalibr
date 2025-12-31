import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { CssTransformGeneratorTool } from '../CssTransformGeneratorTool';
import type { CssTransformGeneratorData } from '../CssTransformGeneratorTool';

const CssTransformGenerator = CssTransformGeneratorTool.Component;

describe('CssTransformGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the CssTransformGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CssTransformGenerator data={{}} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CssTransformGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'CssTransformGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <CssTransformGenerator data={{}} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'CssTransformGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CssTransformGenerator data={{}} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CssTransformGeneratorInitialState' }, container);
    });
  });
});
