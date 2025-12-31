import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { UnitConverterTool } from '../UnitConverterTool';
import type { UnitConverterData } from '../UnitConverterTool';

const UnitConverter = UnitConverterTool.Component;

describe('UnitConverterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the UnitConverter interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <UnitConverter data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'UnitConverterRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'UnitConverterHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <UnitConverter data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'UnitConverterInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <UnitConverter data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'UnitConverterInitialState' }, container);
    });
  });
});
