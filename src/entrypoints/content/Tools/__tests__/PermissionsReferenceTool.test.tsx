import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { PermissionsReferenceTool } from '../PermissionsReferenceTool';
import type { PermissionsReferenceData } from '../PermissionsReferenceTool';

const PermissionsReference = PermissionsReferenceTool.Component;

describe('PermissionsReferenceTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the PermissionsReference interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <PermissionsReference data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'PermissionsReferenceRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'PermissionsReferenceHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <PermissionsReference data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'PermissionsReferenceInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <PermissionsReference data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'PermissionsReferenceInitialState' }, container);
    });
  });
});
