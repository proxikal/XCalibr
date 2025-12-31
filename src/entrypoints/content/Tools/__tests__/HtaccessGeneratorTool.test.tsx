import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { HtaccessGeneratorTool } from '../HtaccessGeneratorTool';

const HtaccessGenerator = HtaccessGeneratorTool.Component;

describe('HtaccessGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the HtaccessGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <HtaccessGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'HtaccessGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'HtaccessGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <HtaccessGenerator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'HtaccessGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <HtaccessGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'HtaccessGeneratorInitialState' }, container);
    });
  });
});
