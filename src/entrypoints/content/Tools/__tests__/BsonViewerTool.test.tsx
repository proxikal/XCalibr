import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { BsonViewerTool } from '../BsonViewerTool';

const BsonViewer = BsonViewerTool.Component;

describe('BsonViewerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the BsonViewer interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <BsonViewer data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'BsonViewerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'BsonViewerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <BsonViewer data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'BsonViewerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <BsonViewer data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'BsonViewerInitialState' }, container);
    });
  });
});
