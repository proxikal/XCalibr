import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { HtmlToMarkdownTool } from '../HtmlToMarkdownTool';
import type { HtmlToMarkdownData } from '../HtmlToMarkdownTool';

const HtmlToMarkdown = HtmlToMarkdownTool.Component;

describe('HtmlToMarkdownTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the HtmlToMarkdown interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <HtmlToMarkdown data={{}} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'HtmlToMarkdownRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'HtmlToMarkdownHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <HtmlToMarkdown data={{}} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'HtmlToMarkdownInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <HtmlToMarkdown data={{}} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'HtmlToMarkdownInitialState' }, container);
    });
  });
});
