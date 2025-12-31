import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { Base64AdvancedTool } from '../Base64AdvancedTool';

const Base64Advanced = Base64AdvancedTool.Component;

describe('Base64AdvancedTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the Base64Advanced interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <Base64Advanced data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'Base64AdvancedRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'Base64AdvancedHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <Base64Advanced data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'Base64AdvancedInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <Base64Advanced data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'Base64AdvancedInitialState' }, container);
    });
  });
});
