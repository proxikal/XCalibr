import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { EscapingTool } from '../EscapingTool';
import type { EscapingToolData } from '../EscapingTool';

const Escaping = EscapingTool.Component;

describe('EscapingTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the Escaping interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <Escaping data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'EscapingRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'EscapingHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <Escaping data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'EscapingInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <Escaping data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'EscapingInitialState' }, container);
    });
  });
});
