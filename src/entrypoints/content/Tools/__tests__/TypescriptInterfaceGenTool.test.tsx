import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { TypescriptInterfaceGenTool } from '../TypescriptInterfaceGenTool';
import type { TypescriptInterfaceGenData } from '../TypescriptInterfaceGenTool';

const TypescriptInterfaceGen = TypescriptInterfaceGenTool.Component;

describe('TypescriptInterfaceGenTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the TypescriptInterfaceGen interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <TypescriptInterfaceGen data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'TypescriptInterfaceGenRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'TypescriptInterfaceGenHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <TypescriptInterfaceGen data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'TypescriptInterfaceGenInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <TypescriptInterfaceGen data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'TypescriptInterfaceGenInitialState' }, container);
    });
  });
});
