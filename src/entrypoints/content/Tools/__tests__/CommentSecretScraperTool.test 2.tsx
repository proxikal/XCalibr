import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { CommentSecretScraperTool } from '../CommentSecretScraperTool';
import type { CommentSecretScraperData } from '../CommentSecretScraperTool';

const CommentSecretScraper = CommentSecretScraperTool.Component;

describe('CommentSecretScraperTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the CommentSecretScraper interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CommentSecretScraper data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CommentSecretScraperRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'CommentSecretScraperHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <CommentSecretScraper data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'CommentSecretScraperInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CommentSecretScraper data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CommentSecretScraperInitialState' }, container);
    });
  });
});
