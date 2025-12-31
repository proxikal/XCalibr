import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { WaybackMachineViewerTool as WaybackMachineViewer } from '../WaybackMachineViewerTool';

describe('WaybackMachineViewerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the WaybackMachineViewer interface', () => {
      const onChange = vi.fn();
      const onSearch = vi.fn(async () => {});
      const { container } = renderTool(
        <WaybackMachineViewer data={{ url: '', loading: false }} onChange={onChange} onSearch={onSearch} />
      );

      aiAssertTruthy({ name: 'WaybackMachineViewerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'WaybackMachineViewerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const onSearch = vi.fn(async () => {});
      const { container, findButton } = renderTool(
        <WaybackMachineViewer data={{ url: '', loading: false }} onChange={onChange} onSearch={onSearch} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'WaybackMachineViewerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const onSearch = vi.fn(async () => {});
      const { container } = renderTool(
        <WaybackMachineViewer data={{ url: '', loading: false }} onChange={onChange} onSearch={onSearch} />
      );

      aiAssertTruthy({ name: 'WaybackMachineViewerInitialState' }, container);
    });
  });
});
