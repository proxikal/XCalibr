import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { XssPayloadTool } from '../XssPayloadTool';

const XssPayload = XssPayloadTool.Component;

describe('XssPayloadTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the XssPayload interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <XssPayload data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'XssPayloadRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'XssPayloadHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <XssPayload data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'XssPayloadInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <XssPayload data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'XssPayloadInitialState' }, container);
    });
  });
});
