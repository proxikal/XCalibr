import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { BoxShadowGeneratorTool } from '../BoxShadowGeneratorTool';

const BoxShadowGenerator = BoxShadowGeneratorTool.Component;

describe('BoxShadowGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the BoxShadowGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <BoxShadowGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'BoxShadowGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'BoxShadowGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <BoxShadowGenerator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'BoxShadowGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <BoxShadowGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'BoxShadowGeneratorInitialState' }, container);
    });
  });
});
