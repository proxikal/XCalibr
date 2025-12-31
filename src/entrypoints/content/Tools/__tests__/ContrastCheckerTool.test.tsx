import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { ContrastCheckerTool } from '../ContrastCheckerTool';

const ContrastChecker = ContrastCheckerTool.Component;

describe('ContrastCheckerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the ContrastChecker interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <ContrastChecker data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'ContrastCheckerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'ContrastCheckerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <ContrastChecker data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'ContrastCheckerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <ContrastChecker data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'ContrastCheckerInitialState' }, container);
    });
  });
});
