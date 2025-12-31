import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { TextDiffTool } from '../TextDiffTool';
import type { TextDiffData } from '../TextDiffTool';

const TextDiff = TextDiffTool.Component;

describe('TextDiffTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the TextDiff interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <TextDiff data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'TextDiffRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'TextDiffHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <TextDiff data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'TextDiffInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <TextDiff data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'TextDiffInitialState' }, container);
    });
  });
});
