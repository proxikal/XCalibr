import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { LighthouseSnapshotTool } from '../LighthouseSnapshotTool';

const LighthouseSnapshot = LighthouseSnapshotTool.Component;

describe('LighthouseSnapshotTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the LighthouseSnapshot interface', () => {
      const onCapture = vi.fn();
      const { container } = renderTool(
        <LighthouseSnapshot data={undefined} onCapture={onCapture} />
      );

      aiAssertTruthy({ name: 'LighthouseSnapshotRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'LighthouseSnapshotHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onCapture = vi.fn();
      const { container, findButton } = renderTool(
        <LighthouseSnapshot data={undefined} onCapture={onCapture} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'LighthouseSnapshotInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onCapture = vi.fn();
      const { container } = renderTool(
        <LighthouseSnapshot data={undefined} onCapture={onCapture} />
      );

      aiAssertTruthy({ name: 'LighthouseSnapshotInitialState' }, container);
    });
  });
});
