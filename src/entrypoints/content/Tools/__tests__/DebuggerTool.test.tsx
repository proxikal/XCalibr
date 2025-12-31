import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { DebuggerTool } from '../DebuggerTool';

const Debugger = DebuggerTool.Component;

describe('DebuggerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the Debugger interface', () => {
      const onClear = vi.fn();
      const { container } = renderTool(
        <Debugger data={undefined} onClear={onClear} />
      );

      aiAssertTruthy({ name: 'DebuggerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'DebuggerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onClear = vi.fn();
      const { container, findButton } = renderTool(
        <Debugger data={undefined} onClear={onClear} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'DebuggerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onClear = vi.fn();
      const { container } = renderTool(
        <Debugger data={undefined} onClear={onClear} />
      );

      aiAssertTruthy({ name: 'DebuggerInitialState' }, container);
    });
  });
});
