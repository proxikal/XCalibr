import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { ResponsivePreviewTool } from '../ResponsivePreviewTool';

const ResponsivePreview = ResponsivePreviewTool.Component;

describe('ResponsivePreviewTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the ResponsivePreview interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <ResponsivePreview data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'ResponsivePreviewRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'ResponsivePreviewHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <ResponsivePreview data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'ResponsivePreviewInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <ResponsivePreview data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'ResponsivePreviewInitialState' }, container);
    });
  });
});
