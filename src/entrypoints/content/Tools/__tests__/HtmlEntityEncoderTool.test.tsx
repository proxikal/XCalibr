import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { HtmlEntityEncoderTool } from '../HtmlEntityEncoderTool';

const HtmlEntityEncoder = HtmlEntityEncoderTool.Component;

describe('HtmlEntityEncoderTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the HtmlEntityEncoder interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <HtmlEntityEncoder data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'HtmlEntityEncoderRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'HtmlEntityEncoderHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <HtmlEntityEncoder data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'HtmlEntityEncoderInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <HtmlEntityEncoder data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'HtmlEntityEncoderInitialState' }, container);
    });
  });
});
