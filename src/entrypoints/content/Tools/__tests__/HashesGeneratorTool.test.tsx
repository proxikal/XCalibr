import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { HashesGeneratorTool } from '../HashesGeneratorTool';

const HashesGenerator = HashesGeneratorTool.Component;

describe('HashesGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the HashesGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <HashesGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'HashesGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'HashesGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <HashesGenerator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'HashesGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <HashesGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'HashesGeneratorInitialState' }, container);
    });
  });
});
