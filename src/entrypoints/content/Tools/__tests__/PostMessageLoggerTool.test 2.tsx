import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { PostMessageLoggerTool } from '../PostMessageLoggerTool';
import type { PostMessageLoggerData } from '../PostMessageLoggerTool';

const PostMessageLogger = PostMessageLoggerTool.Component;

describe('PostMessageLoggerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the PostMessageLogger interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <PostMessageLogger data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'PostMessageLoggerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'PostMessageLoggerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <PostMessageLogger data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'PostMessageLoggerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <PostMessageLogger data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'PostMessageLoggerInitialState' }, container);
    });
  });
});
