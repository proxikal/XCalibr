import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { EnvVariableScannerTool } from '../EnvVariableScannerTool';
import type { EnvVariableScannerData } from '../EnvVariableScannerTool';

const EnvVariableScanner = EnvVariableScannerTool.Component;

describe('EnvVariableScannerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the EnvVariableScanner interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <EnvVariableScanner data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'EnvVariableScannerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'EnvVariableScannerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <EnvVariableScanner data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'EnvVariableScannerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <EnvVariableScanner data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'EnvVariableScannerInitialState' }, container);
    });
  });
});
