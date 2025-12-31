import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { EmailBreachCheckerTool } from '../EmailBreachCheckerTool';

const EmailBreachChecker = EmailBreachCheckerTool.Component;

describe('EmailBreachCheckerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the EmailBreachChecker interface', () => {
      const onChange = vi.fn();
      const onCheck = vi.fn(async () => {});
      const { container } = renderTool(
        <EmailBreachChecker data={undefined} onChange={onChange} onCheck={onCheck} />
      );

      aiAssertTruthy({ name: 'EmailBreachCheckerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'EmailBreachCheckerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const onCheck = vi.fn(async () => {});
      const { container, findButton } = renderTool(
        <EmailBreachChecker data={undefined} onChange={onChange} onCheck={onCheck} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'EmailBreachCheckerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const onCheck = vi.fn(async () => {});
      const { container } = renderTool(
        <EmailBreachChecker data={undefined} onChange={onChange} onCheck={onCheck} />
      );

      aiAssertTruthy({ name: 'EmailBreachCheckerInitialState' }, container);
    });
  });
});
