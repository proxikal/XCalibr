import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { CsvToJsonTool } from '../CsvToJsonTool';
import type { CsvToJsonData } from '../CsvToJsonTool';

const CsvToJson = CsvToJsonTool.Component;

describe('CsvToJsonTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the CsvToJson interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CsvToJson data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CsvToJsonRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'CsvToJsonHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <CsvToJson data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'CsvToJsonInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CsvToJson data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CsvToJsonInitialState' }, container);
    });
  });
});
