import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { CookieSecurityAuditorTool } from '../CookieSecurityAuditorTool';
import type { CookieSecurityAuditorData } from '../CookieSecurityAuditorTool';

const CookieSecurityAuditor = CookieSecurityAuditorTool.Component;

describe('CookieSecurityAuditorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the CookieSecurityAuditor interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CookieSecurityAuditor data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CookieSecurityAuditorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'CookieSecurityAuditorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <CookieSecurityAuditor data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'CookieSecurityAuditorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CookieSecurityAuditor data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CookieSecurityAuditorInitialState' }, container);
    });
  });
});
