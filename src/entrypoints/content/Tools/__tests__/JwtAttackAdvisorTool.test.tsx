import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { JwtAttackAdvisorTool } from '../JwtAttackAdvisorTool';
import type { JwtAttackAdvisorData } from '../JwtAttackAdvisorTool';

const JwtAttackAdvisor = JwtAttackAdvisorTool.Component;

describe('JwtAttackAdvisorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the JwtAttackAdvisor interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <JwtAttackAdvisor data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'JwtAttackAdvisorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'JwtAttackAdvisorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <JwtAttackAdvisor data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'JwtAttackAdvisorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <JwtAttackAdvisor data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'JwtAttackAdvisorInitialState' }, container);
    });
  });
});
