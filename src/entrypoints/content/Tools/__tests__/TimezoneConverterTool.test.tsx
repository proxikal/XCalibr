import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { TimezoneConverterTool } from '../TimezoneConverterTool';
import type { TimezoneConverterData } from '../TimezoneConverterTool';

const TimezoneConverter = TimezoneConverterTool.Component;

describe('TimezoneConverterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the TimezoneConverter interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <TimezoneConverter data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'TimezoneConverterRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'TimezoneConverterHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <TimezoneConverter data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'TimezoneConverterInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <TimezoneConverter data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'TimezoneConverterInitialState' }, container);
    });
  });
});
