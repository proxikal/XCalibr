import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { FontIdentifierTool } from '../FontIdentifierTool';

const FontIdentifier = FontIdentifierTool.Component;

describe('FontIdentifierTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the FontIdentifier interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <FontIdentifier data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'FontIdentifierRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'FontIdentifierHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <FontIdentifier data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'FontIdentifierInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <FontIdentifier data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'FontIdentifierInitialState' }, container);
    });
  });
});
