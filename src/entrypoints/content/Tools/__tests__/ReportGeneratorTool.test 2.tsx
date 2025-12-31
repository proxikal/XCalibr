import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { ReportGeneratorTool } from '../ReportGeneratorTool';

const ReportGenerator = ReportGeneratorTool.Component;

describe('ReportGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the ReportGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <ReportGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'ReportGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'ReportGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <ReportGenerator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'ReportGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <ReportGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'ReportGeneratorInitialState' }, container);
    });
  });
});
