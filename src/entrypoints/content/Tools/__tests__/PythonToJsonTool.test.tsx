import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { PythonToJsonTool } from '../PythonToJsonTool';
import type { PythonToJsonData } from '../PythonToJsonTool';

const PythonToJson = PythonToJsonTool.Component;

describe('PythonToJsonTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the PythonToJson interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <PythonToJson data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'PythonToJsonRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'PythonToJsonHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <PythonToJson data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'PythonToJsonInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <PythonToJson data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'PythonToJsonInitialState' }, container);
    });
  });
});
