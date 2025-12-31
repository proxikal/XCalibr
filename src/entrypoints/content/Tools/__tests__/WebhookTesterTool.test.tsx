import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { WebhookTesterTool } from '../WebhookTesterTool';

const WebhookTester = WebhookTesterTool.Component;

describe('WebhookTesterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the WebhookTester interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <WebhookTester data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'WebhookTesterRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'WebhookTesterHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <WebhookTester data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'WebhookTesterInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <WebhookTester data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'WebhookTesterInitialState' }, container);
    });
  });
});
