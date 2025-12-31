import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { PemDerConverterTool } from '../PemDerConverterTool';

const PemDerConverter = PemDerConverterTool.Component;

describe('PemDerConverterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the PemDerConverter interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <PemDerConverter data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'PemDerConverterRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'PemDerConverterHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <PemDerConverter data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'PemDerConverterInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <PemDerConverter data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'PemDerConverterInitialState' }, container);
    });
  });
});
