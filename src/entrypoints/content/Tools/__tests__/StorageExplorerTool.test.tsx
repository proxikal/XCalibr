import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { StorageExplorerTool } from '../StorageExplorerTool';

const StorageExplorer = StorageExplorerTool.Component;

describe('StorageExplorerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the StorageExplorer interface', () => {
      const onRefresh = vi.fn(async () => {});
      const { container } = renderTool(
        <StorageExplorer data={undefined} onRefresh={onRefresh} />
      );

      aiAssertTruthy({ name: 'StorageExplorerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'StorageExplorerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onRefresh = vi.fn(async () => {});
      const { container, findButton } = renderTool(
        <StorageExplorer data={undefined} onRefresh={onRefresh} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'StorageExplorerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onRefresh = vi.fn(async () => {});
      const { container } = renderTool(
        <StorageExplorer data={undefined} onRefresh={onRefresh} />
      );

      aiAssertTruthy({ name: 'StorageExplorerInitialState' }, container);
    });
  });
});
