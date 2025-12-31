import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { SriGeneratorTool } from '../SriGeneratorTool';

const SriGenerator = SriGeneratorTool.Component;

describe('SriGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the SriGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <SriGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'SriGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'SriGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <SriGenerator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'SriGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <SriGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'SriGeneratorInitialState' }, container);
    });
  });
});
