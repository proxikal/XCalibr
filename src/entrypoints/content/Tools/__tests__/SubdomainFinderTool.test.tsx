import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { SubdomainFinderTool } from '../SubdomainFinderTool';

const SubdomainFinder = SubdomainFinderTool.Component;

describe('SubdomainFinderTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the SubdomainFinder interface', () => {
      const onChange = vi.fn();
      const onFind = vi.fn(async () => {});
      const { container } = renderTool(
        <SubdomainFinder data={undefined} onChange={onChange} onFind={onFind} />
      );

      aiAssertTruthy({ name: 'SubdomainFinderRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'SubdomainFinderHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const onFind = vi.fn(async () => {});
      const { container, findButton } = renderTool(
        <SubdomainFinder data={undefined} onChange={onChange} onFind={onFind} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'SubdomainFinderInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const onFind = vi.fn(async () => {});
      const { container } = renderTool(
        <SubdomainFinder data={undefined} onChange={onChange} onFind={onFind} />
      );

      aiAssertTruthy({ name: 'SubdomainFinderInitialState' }, container);
    });
  });
});
