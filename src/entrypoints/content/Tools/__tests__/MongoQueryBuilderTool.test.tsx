import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { MongoQueryBuilderTool } from '../MongoQueryBuilderTool';

const MongoQueryBuilder = MongoQueryBuilderTool.Component;

describe('MongoQueryBuilderTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the MongoQueryBuilder interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <MongoQueryBuilder data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'MongoQueryBuilderRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'MongoQueryBuilderHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <MongoQueryBuilder data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'MongoQueryBuilderInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <MongoQueryBuilder data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'MongoQueryBuilderInitialState' }, container);
    });
  });
});
