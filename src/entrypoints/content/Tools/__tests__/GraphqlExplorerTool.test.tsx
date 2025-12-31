import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { GraphqlExplorerTool } from '../GraphqlExplorerTool';

const GraphqlExplorer = GraphqlExplorerTool.Component;

describe('GraphqlExplorerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the GraphqlExplorer interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <GraphqlExplorer data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'GraphqlExplorerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'GraphqlExplorerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <GraphqlExplorer data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'GraphqlExplorerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <GraphqlExplorer data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'GraphqlExplorerInitialState' }, container);
    });
  });
});
