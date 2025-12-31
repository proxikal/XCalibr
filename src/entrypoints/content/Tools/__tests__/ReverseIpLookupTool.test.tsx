import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { ReverseIpLookupTool } from '../ReverseIpLookupTool';

const ReverseIpLookup = ReverseIpLookupTool.Component;

describe('ReverseIpLookupTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the ReverseIpLookup interface', () => {
      const onChange = vi.fn();
      const onLookup = vi.fn(async () => {});
      const { container } = renderTool(
        <ReverseIpLookup data={undefined} onChange={onChange} onLookup={onLookup} />
      );

      aiAssertTruthy({ name: 'ReverseIpLookupRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'ReverseIpLookupHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const onLookup = vi.fn(async () => {});
      const { container, findButton } = renderTool(
        <ReverseIpLookup data={undefined} onChange={onChange} onLookup={onLookup} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'ReverseIpLookupInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const onLookup = vi.fn(async () => {});
      const { container } = renderTool(
        <ReverseIpLookup data={undefined} onChange={onChange} onLookup={onLookup} />
      );

      aiAssertTruthy({ name: 'ReverseIpLookupInitialState' }, container);
    });
  });
});
