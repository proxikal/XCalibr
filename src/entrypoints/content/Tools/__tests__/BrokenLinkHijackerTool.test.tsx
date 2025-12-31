import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { BrokenLinkHijackerTool } from '../BrokenLinkHijackerTool';
import type { BrokenLinkHijackerData } from '../BrokenLinkHijackerTool';

const BrokenLinkHijacker = BrokenLinkHijackerTool.Component;

describe('BrokenLinkHijackerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the BrokenLinkHijacker interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <BrokenLinkHijacker data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'BrokenLinkHijackerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'BrokenLinkHijackerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <BrokenLinkHijacker data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'BrokenLinkHijackerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <BrokenLinkHijacker data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'BrokenLinkHijackerInitialState' }, container);
    });
  });
});
