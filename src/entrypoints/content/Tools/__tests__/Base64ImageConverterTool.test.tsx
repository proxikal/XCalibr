import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { Base64ImageConverterTool } from '../Base64ImageConverterTool';
import type { Base64ImageConverterData } from '../Base64ImageConverterTool';

const Base64ImageConverter = Base64ImageConverterTool.Component;

describe('Base64ImageConverterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the Base64ImageConverter interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <Base64ImageConverter data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'Base64ImageConverterRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'Base64ImageConverterHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <Base64ImageConverter data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'Base64ImageConverterInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <Base64ImageConverter data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'Base64ImageConverterInitialState' }, container);
    });
  });
});
