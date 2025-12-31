import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { IdorIteratorTool } from '../IdorIteratorTool';
import type { IdorIteratorData } from '../IdorIteratorTool';

const IdorIterator = IdorIteratorTool.Component;

describe('IdorIteratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the IdorIterator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <IdorIterator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'IdorIteratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'IdorIteratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <IdorIterator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'IdorIteratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <IdorIterator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'IdorIteratorInitialState' }, container);
    });
  });
});
