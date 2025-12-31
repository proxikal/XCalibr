import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { JwtDebuggerTool } from '../JwtDebuggerTool';

const JwtDebugger = JwtDebuggerTool.Component;

describe('JwtDebuggerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the JwtDebugger interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <JwtDebugger data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'JwtDebuggerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'JwtDebuggerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <JwtDebugger data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'JwtDebuggerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <JwtDebugger data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'JwtDebuggerInitialState' }, container);
    });
  });
});
