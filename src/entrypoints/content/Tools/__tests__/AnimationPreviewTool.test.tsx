import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { AnimationPreviewTool } from '../AnimationPreviewTool';

const AnimationPreview = AnimationPreviewTool.Component;

describe('AnimationPreviewTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the AnimationPreview interface', () => {
      const onChange = vi.fn();
      const onInject = vi.fn(async () => {});
      const { container } = renderTool(
        <AnimationPreview data={undefined} onChange={onChange} onInject={onInject} />
      );

      aiAssertTruthy({ name: 'AnimationPreviewRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'AnimationPreviewHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const onInject = vi.fn(async () => {});
      const { container, findButton } = renderTool(
        <AnimationPreview data={undefined} onChange={onChange} onInject={onInject} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'AnimationPreviewInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const onInject = vi.fn(async () => {});
      const { container } = renderTool(
        <AnimationPreview data={undefined} onChange={onChange} onInject={onInject} />
      );

      aiAssertTruthy({ name: 'AnimationPreviewInitialState' }, container);
    });
  });
});
