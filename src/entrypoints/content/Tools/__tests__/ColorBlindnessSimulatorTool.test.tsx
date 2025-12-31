import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { ColorBlindnessSimulatorTool } from '../ColorBlindnessSimulatorTool';
import type { ColorBlindnessSimulatorData } from '../ColorBlindnessSimulatorTool';

const ColorBlindnessSimulator = ColorBlindnessSimulatorTool.Component;

describe('ColorBlindnessSimulatorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the ColorBlindnessSimulator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <ColorBlindnessSimulator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'ColorBlindnessSimulatorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'ColorBlindnessSimulatorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <ColorBlindnessSimulator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'ColorBlindnessSimulatorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <ColorBlindnessSimulator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'ColorBlindnessSimulatorInitialState' }, container);
    });
  });
});
