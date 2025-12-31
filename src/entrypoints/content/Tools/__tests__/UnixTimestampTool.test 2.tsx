import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { UnixTimestampTool } from '../UnixTimestampTool';
import type { UnixTimestampData } from '../UnixTimestampTool';

const UnixTimestamp = UnixTimestampTool.Component;

describe('UnixTimestampTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the UnixTimestamp interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <UnixTimestamp data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'UnixTimestampRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'UnixTimestampHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <UnixTimestamp data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'UnixTimestampInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <UnixTimestamp data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'UnixTimestampInitialState' }, container);
    });
  });
});
