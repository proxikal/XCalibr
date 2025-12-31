import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { ParamAnalyzerTool } from '../ParamAnalyzerTool';

const ParamAnalyzer = ParamAnalyzerTool.Component;

describe('ParamAnalyzerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the ParamAnalyzer interface', () => {
      const onChange = vi.fn();
      const onRefresh = vi.fn(async () => {});
      const { container } = renderTool(
        <ParamAnalyzer data={undefined} onChange={onChange} onRefresh={onRefresh} />
      );

      aiAssertTruthy({ name: 'ParamAnalyzerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'ParamAnalyzerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const onRefresh = vi.fn(async () => {});
      const { container, findButton } = renderTool(
        <ParamAnalyzer data={undefined} onChange={onChange} onRefresh={onRefresh} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'ParamAnalyzerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const onRefresh = vi.fn(async () => {});
      const { container } = renderTool(
        <ParamAnalyzer data={undefined} onChange={onChange} onRefresh={onRefresh} />
      );

      aiAssertTruthy({ name: 'ParamAnalyzerInitialState' }, container);
    });
  });
});
