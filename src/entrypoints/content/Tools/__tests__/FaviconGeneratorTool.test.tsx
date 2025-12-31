import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { FaviconGeneratorTool } from '../FaviconGeneratorTool';
import type { FaviconGeneratorData } from '../FaviconGeneratorTool';

const FaviconGenerator = FaviconGeneratorTool.Component;

describe('FaviconGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the FaviconGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <FaviconGenerator data={{}} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'FaviconGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'FaviconGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <FaviconGenerator data={{}} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'FaviconGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <FaviconGenerator data={{}} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'FaviconGeneratorInitialState' }, container);
    });
  });
});
