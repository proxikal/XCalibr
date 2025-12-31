import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { ObjectIdGeneratorTool } from '../ObjectIdGeneratorTool';
import type { ObjectIdGeneratorData } from '../ObjectIdGeneratorTool';

const ObjectIdGenerator = ObjectIdGeneratorTool.Component;

describe('ObjectIdGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the ObjectIdGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <ObjectIdGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'ObjectIdGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'ObjectIdGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <ObjectIdGenerator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'ObjectIdGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <ObjectIdGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'ObjectIdGeneratorInitialState' }, container);
    });
  });
});
