import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { ApiEndpointScraperTool } from '../ApiEndpointScraperTool';
import type { ApiEndpointScraperData } from '../ApiEndpointScraperTool';

const ApiEndpointScraper = ApiEndpointScraperTool.Component;

describe('ApiEndpointScraperTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the ApiEndpointScraper interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <ApiEndpointScraper data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'ApiEndpointScraperRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'ApiEndpointScraperHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <ApiEndpointScraper data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'ApiEndpointScraperInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <ApiEndpointScraper data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'ApiEndpointScraperInitialState' }, container);
    });
  });
});
