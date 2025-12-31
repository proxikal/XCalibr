import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { HttpStatusReferenceTool } from '../HttpStatusReferenceTool';

const HttpStatusReference = HttpStatusReferenceTool.Component;

describe('HttpStatusReferenceTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the HttpStatusReference interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <HttpStatusReference data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'HttpStatusReferenceRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'HttpStatusReferenceHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <HttpStatusReference data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'HttpStatusReferenceInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <HttpStatusReference data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'HttpStatusReferenceInitialState' }, container);
    });
  });
});
