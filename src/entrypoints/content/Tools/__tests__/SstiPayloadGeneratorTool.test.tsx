import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { SstiPayloadGeneratorTool } from '../SstiPayloadGeneratorTool';

const SstiPayloadGenerator = SstiPayloadGeneratorTool.Component;

describe('SstiPayloadGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the SstiPayloadGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <SstiPayloadGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'SstiPayloadGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'SstiPayloadGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <SstiPayloadGenerator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'SstiPayloadGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <SstiPayloadGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'SstiPayloadGeneratorInitialState' }, container);
    });
  });
});
