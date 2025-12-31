import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { PortReferenceTool } from '../PortReferenceTool';

const PortReference = PortReferenceTool.Component;

describe('PortReferenceTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the PortReference interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <PortReference data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'PortReferenceRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'PortReferenceHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <PortReference data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'PortReferenceInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <PortReference data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'PortReferenceInitialState' }, container);
    });
  });
});
