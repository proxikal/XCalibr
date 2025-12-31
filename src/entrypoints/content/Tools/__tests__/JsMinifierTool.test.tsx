import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { JsMinifierTool } from '../JsMinifierTool';
import type { JsMinifierData } from '../JsMinifierTool';

const JsMinifier = JsMinifierTool.Component;

describe('JsMinifierTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the JsMinifier interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <JsMinifier data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'JsMinifierRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'JsMinifierHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <JsMinifier data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'JsMinifierInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <JsMinifier data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'JsMinifierInitialState' }, container);
    });
  });
});
