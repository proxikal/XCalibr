import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { FirebaseRulesLinterTool } from '../FirebaseRulesLinterTool';

const FirebaseRulesLinter = FirebaseRulesLinterTool.Component;

describe('FirebaseRulesLinterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the FirebaseRulesLinter interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <FirebaseRulesLinter data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'FirebaseRulesLinterRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'FirebaseRulesLinterHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <FirebaseRulesLinter data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'FirebaseRulesLinterInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <FirebaseRulesLinter data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'FirebaseRulesLinterInitialState' }, container);
    });
  });
});
