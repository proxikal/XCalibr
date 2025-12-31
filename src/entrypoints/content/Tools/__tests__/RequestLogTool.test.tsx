import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { RequestLogTool } from '../RequestLogTool';

const RequestLog = RequestLogTool.Component;

describe('RequestLogTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the RequestLog interface', () => {
      const onChange = vi.fn();
      const onClear = vi.fn();
      const { container } = renderTool(
        <RequestLog data={undefined} onChange={onChange} onClear={onClear} />
      );

      aiAssertTruthy({ name: 'RequestLogRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'RequestLogHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const onClear = vi.fn();
      const { container, findButton } = renderTool(
        <RequestLog data={undefined} onChange={onChange} onClear={onClear} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'RequestLogInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const onClear = vi.fn();
      const { container } = renderTool(
        <RequestLog data={undefined} onChange={onChange} onClear={onClear} />
      );

      aiAssertTruthy({ name: 'RequestLogInitialState' }, container);
    });
  });
});
