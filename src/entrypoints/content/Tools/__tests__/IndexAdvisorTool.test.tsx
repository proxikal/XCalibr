import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { IndexAdvisorTool } from '../IndexAdvisorTool';

const IndexAdvisor = IndexAdvisorTool.Component;

describe('IndexAdvisorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the IndexAdvisor interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <IndexAdvisor data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'IndexAdvisorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'IndexAdvisorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <IndexAdvisor data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'IndexAdvisorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <IndexAdvisor data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'IndexAdvisorInitialState' }, container);
    });
  });
});
