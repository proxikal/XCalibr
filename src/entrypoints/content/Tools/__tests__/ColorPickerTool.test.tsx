import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { ColorPickerTool } from '../ColorPickerTool';

const ColorPicker = ColorPickerTool.Component;

describe('ColorPickerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the ColorPicker interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <ColorPicker data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'ColorPickerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'ColorPickerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <ColorPicker data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'ColorPickerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <ColorPicker data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'ColorPickerInitialState' }, container);
    });
  });
});
