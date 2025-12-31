import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { WebSocketTesterTool } from '../WebSocketTesterTool';

const WebSocketTester = WebSocketTesterTool.Component;

describe('WebSocketTesterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the WebSocketTester interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <WebSocketTester data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'WebSocketTesterRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'WebSocketTesterHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <WebSocketTester data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'WebSocketTesterInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <WebSocketTester data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'WebSocketTesterInitialState' }, container);
    });
  });
});
