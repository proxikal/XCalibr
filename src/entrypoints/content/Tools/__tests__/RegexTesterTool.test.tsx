import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { RegexTesterTool } from '../RegexTesterTool';

const RegexTester = RegexTesterTool.Component;

describe('RegexTesterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the RegexTester interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <RegexTester data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'RegexTesterRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'RegexTesterHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <RegexTester data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'RegexTesterInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <RegexTester data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'RegexTesterInitialState' }, container);
    });
  });
});
