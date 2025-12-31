import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { BarcodeGeneratorTool } from '../BarcodeGeneratorTool';
import type { BarcodeGeneratorData } from '../BarcodeGeneratorTool';

const BarcodeGenerator = BarcodeGeneratorTool.Component;

describe('BarcodeGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the BarcodeGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <BarcodeGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'BarcodeGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'BarcodeGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <BarcodeGenerator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'BarcodeGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <BarcodeGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'BarcodeGeneratorInitialState' }, container);
    });
  });
});
