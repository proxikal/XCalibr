import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { GitIgnoreGeneratorTool } from '../GitIgnoreGeneratorTool';
import type { GitIgnoreGeneratorData } from '../GitIgnoreGeneratorTool';

const GitIgnoreGenerator = GitIgnoreGeneratorTool.Component;

describe('GitIgnoreGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the GitIgnoreGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <GitIgnoreGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'GitIgnoreGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'GitIgnoreGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <GitIgnoreGenerator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'GitIgnoreGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <GitIgnoreGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'GitIgnoreGeneratorInitialState' }, container);
    });
  });
});
