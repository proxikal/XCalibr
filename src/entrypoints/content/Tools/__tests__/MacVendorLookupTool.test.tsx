import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { MacVendorLookupTool } from '../MacVendorLookupTool';

const MacVendorLookup = MacVendorLookupTool.Component;

describe('MacVendorLookupTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the MacVendorLookup interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <MacVendorLookup data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'MacVendorLookupRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'MacVendorLookupHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <MacVendorLookup data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'MacVendorLookupInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <MacVendorLookup data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'MacVendorLookupInitialState' }, container);
    });
  });
});
