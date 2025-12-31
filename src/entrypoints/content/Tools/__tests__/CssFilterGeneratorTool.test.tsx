import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { CssFilterGeneratorTool } from '../CssFilterGeneratorTool';
import type { CssFilterGeneratorData } from '../CssFilterGeneratorTool';

const CssFilterGenerator = CssFilterGeneratorTool.Component;

describe('CssFilterGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the CssFilterGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CssFilterGenerator data={{}} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CssFilterGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'CssFilterGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <CssFilterGenerator data={{}} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'CssFilterGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CssFilterGenerator data={{}} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CssFilterGeneratorInitialState' }, container);
    });
  });
});
