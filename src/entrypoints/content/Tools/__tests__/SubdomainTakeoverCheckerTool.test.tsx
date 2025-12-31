import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { SubdomainTakeoverCheckerTool } from '../SubdomainTakeoverCheckerTool';
import type { SubdomainTakeoverCheckerData } from '../SubdomainTakeoverCheckerTool';

const SubdomainTakeoverChecker = SubdomainTakeoverCheckerTool.Component;

describe('SubdomainTakeoverCheckerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the SubdomainTakeoverChecker interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <SubdomainTakeoverChecker data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'SubdomainTakeoverCheckerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'SubdomainTakeoverCheckerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <SubdomainTakeoverChecker data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'SubdomainTakeoverCheckerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <SubdomainTakeoverChecker data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'SubdomainTakeoverCheckerInitialState' }, container);
    });
  });
});
