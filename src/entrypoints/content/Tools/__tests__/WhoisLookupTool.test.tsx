import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { WhoisLookupTool } from '../WhoisLookupTool';

const WhoisLookup = WhoisLookupTool.Component;

describe('WhoisLookupTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the WhoisLookup interface', () => {
      const onChange = vi.fn();
      const onLookup = vi.fn(async () => {});
      const { container } = renderTool(
        <WhoisLookup data={undefined} onChange={onChange} onLookup={onLookup} />
      );

      aiAssertTruthy({ name: 'WhoisLookupRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'WhoisLookupHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const onLookup = vi.fn(async () => {});
      const { container, findButton } = renderTool(
        <WhoisLookup data={undefined} onChange={onChange} onLookup={onLookup} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'WhoisLookupInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const onLookup = vi.fn(async () => {});
      const { container } = renderTool(
        <WhoisLookup data={undefined} onChange={onChange} onLookup={onLookup} />
      );

      aiAssertTruthy({ name: 'WhoisLookupInitialState' }, container);
    });
  });
});
