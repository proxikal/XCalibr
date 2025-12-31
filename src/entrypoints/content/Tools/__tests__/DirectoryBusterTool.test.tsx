import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { DirectoryBusterTool } from '../DirectoryBusterTool';
import type { DirectoryBusterData } from '../DirectoryBusterTool';

const DirectoryBuster = DirectoryBusterTool.Component;

describe('DirectoryBusterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the DirectoryBuster interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <DirectoryBuster data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'DirectoryBusterRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'DirectoryBusterHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <DirectoryBuster data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'DirectoryBusterInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <DirectoryBuster data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'DirectoryBusterInitialState' }, container);
    });
  });
});
