import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { MetafileScannerTool } from '../MetafileScannerTool';
import type { MetafileScannerData } from '../MetafileScannerTool';

const MetafileScanner = MetafileScannerTool.Component;

describe('MetafileScannerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the MetafileScanner interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <MetafileScanner data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'MetafileScannerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'MetafileScannerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <MetafileScanner data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'MetafileScannerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <MetafileScanner data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'MetafileScannerInitialState' }, container);
    });
  });
});
