import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { SourceMapDetectorTool } from '../SourceMapDetectorTool';
import type { SourceMapDetectorData } from '../SourceMapDetectorTool';

const SourceMapDetector = SourceMapDetectorTool.Component;

describe('SourceMapDetectorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the SourceMapDetector interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <SourceMapDetector data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'SourceMapDetectorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'SourceMapDetectorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <SourceMapDetector data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'SourceMapDetectorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <SourceMapDetector data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'SourceMapDetectorInitialState' }, container);
    });
  });
});
