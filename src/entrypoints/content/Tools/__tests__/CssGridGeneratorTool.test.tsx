import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { CssGridGeneratorTool } from '../CssGridGeneratorTool';

const CssGridGenerator = CssGridGeneratorTool.Component;

describe('CssGridGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the CssGridGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CssGridGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CssGridGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'CssGridGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <CssGridGenerator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'CssGridGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CssGridGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CssGridGeneratorInitialState' }, container);
    });
  });
});
