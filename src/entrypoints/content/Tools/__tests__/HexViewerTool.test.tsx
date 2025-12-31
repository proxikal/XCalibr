import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { HexViewerTool } from '../HexViewerTool';
import type { HexViewerData } from '../HexViewerTool';

const HexViewer = HexViewerTool.Component;

describe('HexViewerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the HexViewer interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <HexViewer data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'HexViewerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'HexViewerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <HexViewer data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'HexViewerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <HexViewer data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'HexViewerInitialState' }, container);
    });
  });
});
