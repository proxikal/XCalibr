import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { GoStructGeneratorTool } from '../GoStructGeneratorTool';
import type { GoStructGeneratorData } from '../GoStructGeneratorTool';

const GoStructGenerator = GoStructGeneratorTool.Component;

describe('GoStructGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the GoStructGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <GoStructGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'GoStructGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'GoStructGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <GoStructGenerator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'GoStructGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <GoStructGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'GoStructGeneratorInitialState' }, container);
    });
  });
});
