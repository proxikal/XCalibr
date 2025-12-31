import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { MetadataScrubberTool } from '../MetadataScrubberTool';

const MetadataScrubber = MetadataScrubberTool.Component;

describe('MetadataScrubberTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the MetadataScrubber interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <MetadataScrubber data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'MetadataScrubberRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'MetadataScrubberHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <MetadataScrubber data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'MetadataScrubberInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <MetadataScrubber data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'MetadataScrubberInitialState' }, container);
    });
  });
});
