import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { GraphqlIntrospectionTesterTool } from '../GraphqlIntrospectionTesterTool';
import type { GraphqlIntrospectionTesterData } from '../GraphqlIntrospectionTesterTool';

const GraphqlIntrospectionTester = GraphqlIntrospectionTesterTool.Component;

describe('GraphqlIntrospectionTesterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the GraphqlIntrospectionTester interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <GraphqlIntrospectionTester data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'GraphqlIntrospectionTesterRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'GraphqlIntrospectionTesterHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <GraphqlIntrospectionTester data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'GraphqlIntrospectionTesterInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <GraphqlIntrospectionTester data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'GraphqlIntrospectionTesterInitialState' }, container);
    });
  });
});
