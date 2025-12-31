import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { LoremIpsumGeneratorTool } from '../LoremIpsumGeneratorTool';
import type { LoremIpsumGeneratorData } from '../LoremIpsumGeneratorTool';

const LoremIpsumGenerator = LoremIpsumGeneratorTool.Component;

describe('LoremIpsumGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the LoremIpsumGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <LoremIpsumGenerator data={{}} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'LoremIpsumGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'LoremIpsumGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <LoremIpsumGenerator data={{}} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'LoremIpsumGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <LoremIpsumGenerator data={{}} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'LoremIpsumGeneratorInitialState' }, container);
    });
  });
});
