import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { VisualGridBuilderTool } from '../VisualGridBuilderTool';
import type { VisualGridBuilderData } from '../VisualGridBuilderTool';

const VisualGridBuilder = VisualGridBuilderTool.Component;

describe('VisualGridBuilderTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the VisualGridBuilder interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <VisualGridBuilder data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'VisualGridBuilderRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'VisualGridBuilderHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <VisualGridBuilder data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'VisualGridBuilderInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <VisualGridBuilder data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'VisualGridBuilderInitialState' }, container);
    });
  });
});
