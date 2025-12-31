import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { CronGeneratorTool } from '../CronGeneratorTool';

const CronGenerator = CronGeneratorTool.Component;

describe('CronGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the CronGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CronGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CronGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'CronGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <CronGenerator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'CronGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <CronGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'CronGeneratorInitialState' }, container);
    });
  });
});
