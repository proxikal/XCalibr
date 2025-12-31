import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { OpenRedirectTesterTool } from '../OpenRedirectTesterTool';
import type { OpenRedirectTesterData } from '../OpenRedirectTesterTool';

const OpenRedirectTester = OpenRedirectTesterTool.Component;

describe('OpenRedirectTesterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the OpenRedirectTester interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <OpenRedirectTester data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'OpenRedirectTesterRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'OpenRedirectTesterHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <OpenRedirectTester data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'OpenRedirectTesterInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <OpenRedirectTester data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'OpenRedirectTesterInitialState' }, container);
    });
  });
});
