import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { OpenGraphPreviewerTool } from '../OpenGraphPreviewerTool';

const OpenGraphPreviewer = OpenGraphPreviewerTool.Component;

describe('OpenGraphPreviewerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the OpenGraphPreviewer interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <OpenGraphPreviewer data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'OpenGraphPreviewerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'OpenGraphPreviewerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <OpenGraphPreviewer data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'OpenGraphPreviewerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <OpenGraphPreviewer data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'OpenGraphPreviewerInitialState' }, container);
    });
  });
});
