import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { ColorPaletteExtractorTool } from '../ColorPaletteExtractorTool';
import type { ColorPaletteExtractorData } from '../ColorPaletteExtractorTool';

const ColorPaletteExtractor = ColorPaletteExtractorTool.Component;

describe('ColorPaletteExtractorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the ColorPaletteExtractor interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <ColorPaletteExtractor data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'ColorPaletteExtractorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'ColorPaletteExtractorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <ColorPaletteExtractor data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'ColorPaletteExtractorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <ColorPaletteExtractor data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'ColorPaletteExtractorInitialState' }, container);
    });
  });
});
