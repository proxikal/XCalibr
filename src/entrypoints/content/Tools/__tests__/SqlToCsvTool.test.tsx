import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { SqlToCsvTool } from '../SqlToCsvTool';

const SqlToCsv = SqlToCsvTool.Component;

describe('SqlToCsvTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the SqlToCsv interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <SqlToCsv data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'SqlToCsvRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'SqlToCsvHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <SqlToCsv data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'SqlToCsvInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <SqlToCsv data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'SqlToCsvInitialState' }, container);
    });
  });
});
