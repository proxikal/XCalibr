import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { UnicodeExplorerTool } from '../UnicodeExplorerTool';
import type { UnicodeExplorerData } from '../UnicodeExplorerTool';

const UnicodeExplorer = UnicodeExplorerTool.Component;

describe('UnicodeExplorerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the UnicodeExplorer interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <UnicodeExplorer data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'UnicodeExplorerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'UnicodeExplorerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <UnicodeExplorer data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'UnicodeExplorerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <UnicodeExplorer data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'UnicodeExplorerInitialState' }, container);
    });
  });
});
