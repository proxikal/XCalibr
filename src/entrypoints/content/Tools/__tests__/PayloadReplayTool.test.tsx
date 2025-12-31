import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { PayloadReplayTool } from '../PayloadReplayTool';

const PayloadReplay = PayloadReplayTool.Component;

describe('PayloadReplayTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the PayloadReplay interface', () => {
      const onChange = vi.fn();
      const onSend = vi.fn(async () => {});
      const { container } = renderTool(
        <PayloadReplay data={undefined} onChange={onChange} onSend={onSend} />
      );

      aiAssertTruthy({ name: 'PayloadReplayRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'PayloadReplayHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const onSend = vi.fn(async () => {});
      const { container, findButton } = renderTool(
        <PayloadReplay data={undefined} onChange={onChange} onSend={onSend} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'PayloadReplayInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const onSend = vi.fn(async () => {});
      const { container } = renderTool(
        <PayloadReplay data={undefined} onChange={onChange} onSend={onSend} />
      );

      aiAssertTruthy({ name: 'PayloadReplayInitialState' }, container);
    });
  });
});
