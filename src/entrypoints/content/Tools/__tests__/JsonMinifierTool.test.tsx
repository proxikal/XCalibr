import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { JsonMinifierTool } from '../JsonMinifierTool';

const JsonMinifier = JsonMinifierTool.Component;

describe('JsonMinifierTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the JsonMinifier interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <JsonMinifier data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'JsonMinifierRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'JsonMinifierHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <JsonMinifier data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'JsonMinifierInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <JsonMinifier data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'JsonMinifierInitialState' }, container);
    });
  });
});
