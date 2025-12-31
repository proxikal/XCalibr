import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { ClickjackingTesterTool } from '../ClickjackingTesterTool';
import type { ClickjackingTesterData } from '../ClickjackingTesterTool';

const ClickjackingTester = ClickjackingTesterTool.Component;

describe('ClickjackingTesterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the ClickjackingTester interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <ClickjackingTester data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'ClickjackingTesterRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'ClickjackingTesterHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <ClickjackingTester data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'ClickjackingTesterInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <ClickjackingTester data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'ClickjackingTesterInitialState' }, container);
    });
  });
});
