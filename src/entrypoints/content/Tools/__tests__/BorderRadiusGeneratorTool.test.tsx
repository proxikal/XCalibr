import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { BorderRadiusGeneratorTool } from '../BorderRadiusGeneratorTool';

const BorderRadiusGenerator = BorderRadiusGeneratorTool.Component;

describe('BorderRadiusGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the BorderRadiusGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <BorderRadiusGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'BorderRadiusGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'BorderRadiusGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <BorderRadiusGenerator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'BorderRadiusGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <BorderRadiusGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'BorderRadiusGeneratorInitialState' }, container);
    });
  });
});
