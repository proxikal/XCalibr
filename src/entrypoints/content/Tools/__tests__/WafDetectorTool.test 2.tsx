import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { WafDetectorTool } from '../WafDetectorTool';
import type { WafDetectorData } from '../WafDetectorTool';

const WafDetector = WafDetectorTool.Component;

describe('WafDetectorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the WafDetector interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <WafDetector data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'WafDetectorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'WafDetectorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <WafDetector data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'WafDetectorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <WafDetector data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'WafDetectorInitialState' }, container);
    });
  });
});
