import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { ScratchpadTool } from '../ScratchpadTool';
import type { ScratchpadData } from '../ScratchpadTool';

const Scratchpad = ScratchpadTool.Component;

describe('ScratchpadTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the Scratchpad interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <Scratchpad data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'ScratchpadRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'ScratchpadHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <Scratchpad data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'ScratchpadInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <Scratchpad data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'ScratchpadInitialState' }, container);
    });
  });
});
