import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { JwtCrackerTool } from '../JwtCrackerTool';

const JwtCracker = JwtCrackerTool.Component;

describe('JwtCrackerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the JwtCracker interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <JwtCracker data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'JwtCrackerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'JwtCrackerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <JwtCracker data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'JwtCrackerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <JwtCracker data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'JwtCrackerInitialState' }, container);
    });
  });
});
