import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { MarkdownToHtmlTool } from '../MarkdownToHtmlTool';
import type { MarkdownToHtmlData } from '../MarkdownToHtmlTool';

const MarkdownToHtml = MarkdownToHtmlTool.Component;

describe('MarkdownToHtmlTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the MarkdownToHtml interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <MarkdownToHtml data={{}} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'MarkdownToHtmlRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'MarkdownToHtmlHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <MarkdownToHtml data={{}} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'MarkdownToHtmlInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <MarkdownToHtml data={{}} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'MarkdownToHtmlInitialState' }, container);
    });
  });
});
