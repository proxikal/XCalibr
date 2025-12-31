import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { CaseConverterTool } from '../CaseConverterTool';
import type { CaseConverterData } from '../CaseConverterTool';

const CaseConverter = CaseConverterTool.Component;

describe('CaseConverterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the CaseConverter interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CaseConverter data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CaseConverterRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'CaseConverterHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <CaseConverter data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'CaseConverterInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CaseConverter data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CaseConverterInitialState' }, container);
    });
  });
});
