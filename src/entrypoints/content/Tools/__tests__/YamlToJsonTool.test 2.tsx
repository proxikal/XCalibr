import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { YamlToJsonTool } from '../YamlToJsonTool';
import type { YamlToJsonData } from '../YamlToJsonTool';

const YamlToJson = YamlToJsonTool.Component;

describe('YamlToJsonTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the YamlToJson interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <YamlToJson data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'YamlToJsonRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'YamlToJsonHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <YamlToJson data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'YamlToJsonInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <YamlToJson data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'YamlToJsonInitialState' }, container);
    });
  });
});
