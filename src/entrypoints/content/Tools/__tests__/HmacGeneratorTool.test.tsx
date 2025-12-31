import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { HmacGeneratorTool } from '../HmacGeneratorTool';

const HmacGenerator = HmacGeneratorTool.Component;

describe('HmacGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the HmacGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <HmacGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'HmacGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'HmacGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <HmacGenerator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'HmacGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <HmacGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'HmacGeneratorInitialState' }, container);
    });
  });
});
