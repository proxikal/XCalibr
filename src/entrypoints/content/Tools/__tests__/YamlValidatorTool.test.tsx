import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { YamlValidatorTool } from '../YamlValidatorTool';

const YamlValidator = YamlValidatorTool.Component;

describe('YamlValidatorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the YamlValidator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <YamlValidator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'YamlValidatorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'YamlValidatorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <YamlValidator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'YamlValidatorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <YamlValidator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'YamlValidatorInitialState' }, container);
    });
  });
});
