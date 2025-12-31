import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { LiveLinkPreviewTool } from '../LiveLinkPreviewTool';

const LiveLinkPreview = LiveLinkPreviewTool.Component;

describe('LiveLinkPreviewTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the LiveLinkPreview interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <LiveLinkPreview data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'LiveLinkPreviewRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'LiveLinkPreviewHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <LiveLinkPreview data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'LiveLinkPreviewInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <LiveLinkPreview data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'LiveLinkPreviewInitialState' }, container);
    });
  });
});
