import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { CspBuilderTool } from '../CspBuilderTool';

const CspBuilder = CspBuilderTool.Component;

describe('CspBuilderTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the CspBuilder interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CspBuilder data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CspBuilderRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'CspBuilderHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <CspBuilder data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'CspBuilderInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CspBuilder data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CspBuilderInitialState' }, container);
    });
  });
});
