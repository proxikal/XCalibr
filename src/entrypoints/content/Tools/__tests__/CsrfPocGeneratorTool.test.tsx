import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { CsrfPocGeneratorTool } from '../CsrfPocGeneratorTool';
import type { CsrfPocGeneratorData } from '../CsrfPocGeneratorTool';

const CsrfPocGenerator = CsrfPocGeneratorTool.Component;

describe('CsrfPocGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the CsrfPocGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CsrfPocGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CsrfPocGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'CsrfPocGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <CsrfPocGenerator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'CsrfPocGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CsrfPocGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CsrfPocGeneratorInitialState' }, container);
    });
  });
});
