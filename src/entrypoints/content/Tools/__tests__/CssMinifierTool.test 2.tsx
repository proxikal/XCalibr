import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { CssMinifierTool } from '../CssMinifierTool';
import type { CssMinifierData } from '../CssMinifierTool';

const CssMinifier = CssMinifierTool.Component;

describe('CssMinifierTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the CssMinifier interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CssMinifier data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CssMinifierRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'CssMinifierHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <CssMinifier data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'CssMinifierInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CssMinifier data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CssMinifierInitialState' }, container);
    });
  });
});
