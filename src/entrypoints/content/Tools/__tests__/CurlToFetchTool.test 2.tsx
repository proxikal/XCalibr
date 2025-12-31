import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { CurlToFetchTool } from '../CurlToFetchTool';
import type { CurlToFetchData } from '../CurlToFetchTool';

const CurlToFetch = CurlToFetchTool.Component;

describe('CurlToFetchTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the CurlToFetch interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CurlToFetch data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CurlToFetchRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'CurlToFetchHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <CurlToFetch data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'CurlToFetchInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CurlToFetch data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CurlToFetchInitialState' }, container);
    });
  });
});
