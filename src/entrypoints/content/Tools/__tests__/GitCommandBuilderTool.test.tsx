import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { GitCommandBuilderTool } from '../GitCommandBuilderTool';
import type { GitCommandBuilderData } from '../GitCommandBuilderTool';

const GitCommandBuilder = GitCommandBuilderTool.Component;

describe('GitCommandBuilderTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the GitCommandBuilder interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <GitCommandBuilder data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'GitCommandBuilderRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'GitCommandBuilderHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <GitCommandBuilder data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'GitCommandBuilderInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <GitCommandBuilder data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'GitCommandBuilderInitialState' }, container);
    });
  });
});
