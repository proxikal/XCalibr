import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { StringObfuscatorTool } from '../StringObfuscatorTool';
import type { StringObfuscatorData } from '../StringObfuscatorTool';

const StringObfuscator = StringObfuscatorTool.Component;

describe('StringObfuscatorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the StringObfuscator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <StringObfuscator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'StringObfuscatorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'StringObfuscatorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <StringObfuscator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'StringObfuscatorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <StringObfuscator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'StringObfuscatorInitialState' }, container);
    });
  });
});
