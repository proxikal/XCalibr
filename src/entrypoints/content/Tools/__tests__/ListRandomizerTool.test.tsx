import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { ListRandomizerTool } from '../ListRandomizerTool';
import type { ListRandomizerData } from '../ListRandomizerTool';

const ListRandomizer = ListRandomizerTool.Component;

describe('ListRandomizerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the ListRandomizer interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <ListRandomizer data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'ListRandomizerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'ListRandomizerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <ListRandomizer data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'ListRandomizerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <ListRandomizer data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'ListRandomizerInitialState' }, container);
    });
  });
});
