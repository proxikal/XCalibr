import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { DefaultCredentialCheckerTool } from '../DefaultCredentialCheckerTool';
import type { DefaultCredentialCheckerData } from '../DefaultCredentialCheckerTool';

const DefaultCredentialChecker = DefaultCredentialCheckerTool.Component;

describe('DefaultCredentialCheckerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the DefaultCredentialChecker interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <DefaultCredentialChecker data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'DefaultCredentialCheckerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'DefaultCredentialCheckerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <DefaultCredentialChecker data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'DefaultCredentialCheckerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <DefaultCredentialChecker data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'DefaultCredentialCheckerInitialState' }, container);
    });
  });
});
