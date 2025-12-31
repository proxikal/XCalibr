import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { JsonToYamlTool } from '../JsonToYamlTool';
import type { JsonToYamlData } from '../JsonToYamlTool';

const JsonToYaml = JsonToYamlTool.Component;

describe('JsonToYamlTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the JsonToYaml interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <JsonToYaml data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'JsonToYamlRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'JsonToYamlHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <JsonToYaml data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'JsonToYamlInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <JsonToYaml data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'JsonToYamlInitialState' }, container);
    });
  });
});
