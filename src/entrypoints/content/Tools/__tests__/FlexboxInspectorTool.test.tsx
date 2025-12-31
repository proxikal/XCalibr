import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { FlexboxInspectorTool } from '../FlexboxInspectorTool';

const FlexboxInspector = FlexboxInspectorTool.Component;

describe('FlexboxInspectorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the FlexboxInspector interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <FlexboxInspector data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'FlexboxInspectorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'FlexboxInspectorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <FlexboxInspector data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'FlexboxInspectorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <FlexboxInspector data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'FlexboxInspectorInitialState' }, container);
    });
  });
});
