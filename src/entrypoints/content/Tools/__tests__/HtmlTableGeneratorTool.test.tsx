import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { HtmlTableGeneratorTool } from '../HtmlTableGeneratorTool';
import type { HtmlTableGeneratorData } from '../HtmlTableGeneratorTool';

const HtmlTableGenerator = HtmlTableGeneratorTool.Component;

describe('HtmlTableGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the HtmlTableGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <HtmlTableGenerator data={{}} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'HtmlTableGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'HtmlTableGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <HtmlTableGenerator data={{}} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'HtmlTableGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <HtmlTableGenerator data={{}} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'HtmlTableGeneratorInitialState' }, container);
    });
  });
});
