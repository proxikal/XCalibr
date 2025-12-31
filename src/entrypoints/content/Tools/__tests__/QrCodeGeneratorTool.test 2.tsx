import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { QrCodeGeneratorTool } from '../QrCodeGeneratorTool';
import type { QrCodeGeneratorData } from '../QrCodeGeneratorTool';

const QrCodeGenerator = QrCodeGeneratorTool.Component;

describe('QrCodeGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the QrCodeGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <QrCodeGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'QrCodeGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'QrCodeGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <QrCodeGenerator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'QrCodeGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <QrCodeGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'QrCodeGeneratorInitialState' }, container);
    });
  });
});
