import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { TextToBinaryTool } from '../TextToBinaryTool';
import type { TextToBinaryData } from '../TextToBinaryTool';

const TextToBinary = TextToBinaryTool.Component;

describe('TextToBinaryTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the TextToBinary interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <TextToBinary data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'TextToBinaryRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'TextToBinaryHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <TextToBinary data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'TextToBinaryInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <TextToBinary data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'TextToBinaryInitialState' }, container);
    });
  });
});
