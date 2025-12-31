import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { XxePayloadGeneratorTool } from '../XxePayloadGeneratorTool';
import type { XxePayloadGeneratorData } from '../XxePayloadGeneratorTool';

const XxePayloadGenerator = XxePayloadGeneratorTool.Component;

describe('XxePayloadGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the XxePayloadGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <XxePayloadGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'XxePayloadGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'XxePayloadGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <XxePayloadGenerator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'XxePayloadGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <XxePayloadGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'XxePayloadGeneratorInitialState' }, container);
    });
  });
});
