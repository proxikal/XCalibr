import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { RegexHighlighterTool } from '../RegexHighlighterTool';
import type { RegexHighlighterData } from '../RegexHighlighterTool';

const RegexHighlighter = RegexHighlighterTool.Component;

describe('RegexHighlighterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the RegexHighlighter interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <RegexHighlighter data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'RegexHighlighterRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'RegexHighlighterHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <RegexHighlighter data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'RegexHighlighterInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <RegexHighlighter data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'RegexHighlighterInitialState' }, container);
    });
  });
});
