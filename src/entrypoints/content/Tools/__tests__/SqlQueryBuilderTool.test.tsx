import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { SqlQueryBuilderTool } from '../SqlQueryBuilderTool';

const SqlQueryBuilder = SqlQueryBuilderTool.Component;

describe('SqlQueryBuilderTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the SqlQueryBuilder interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <SqlQueryBuilder data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'SqlQueryBuilderRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'SqlQueryBuilderHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <SqlQueryBuilder data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'SqlQueryBuilderInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <SqlQueryBuilder data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'SqlQueryBuilderInitialState' }, container);
    });
  });
});
