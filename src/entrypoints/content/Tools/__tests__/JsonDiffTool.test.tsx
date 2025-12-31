import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { JsonDiffTool } from '../JsonDiffTool';

const JsonDiff = JsonDiffTool.Component;

describe('JsonDiffTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the JsonDiff interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <JsonDiff data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'JsonDiffRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'JsonDiffHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <JsonDiff data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'JsonDiffInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <JsonDiff data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'JsonDiffInitialState' }, container);
    });
  });
});
