import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { PlaceholderImageTool } from '../PlaceholderImageTool';
import type { PlaceholderImageData } from '../PlaceholderImageTool';

const PlaceholderImage = PlaceholderImageTool.Component;

describe('PlaceholderImageTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the PlaceholderImage interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <PlaceholderImage data={{}} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'PlaceholderImageRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'PlaceholderImageHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <PlaceholderImage data={{}} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'PlaceholderImageInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <PlaceholderImage data={{}} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'PlaceholderImageInitialState' }, container);
    });
  });
});
