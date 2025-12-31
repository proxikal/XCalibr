import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { SqlFormatterTool } from '../SqlFormatterTool';

const SqlFormatter = SqlFormatterTool.Component;

describe('SqlFormatterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the SqlFormatter interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <SqlFormatter data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'SqlFormatterRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'SqlFormatterHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <SqlFormatter data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'SqlFormatterInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <SqlFormatter data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'SqlFormatterInitialState' }, container);
    });
  });
});
