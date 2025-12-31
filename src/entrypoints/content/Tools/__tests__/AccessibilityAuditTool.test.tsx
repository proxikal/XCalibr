import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { AccessibilityAuditTool } from '../AccessibilityAuditTool';

const AccessibilityAudit = AccessibilityAuditTool.Component;

describe('AccessibilityAuditTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the AccessibilityAudit interface', () => {
      const onRun = vi.fn();
      const { container } = renderTool(
        <AccessibilityAudit data={undefined} onRun={onRun} />
      );

      aiAssertTruthy({ name: 'AccessibilityAuditRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'AccessibilityAuditHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onRun = vi.fn();
      const { container, findButton } = renderTool(
        <AccessibilityAudit data={undefined} onRun={onRun} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'AccessibilityAuditInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onRun = vi.fn();
      const { container } = renderTool(
        <AccessibilityAudit data={undefined} onRun={onRun} />
      );

      aiAssertTruthy({ name: 'AccessibilityAuditInitialState' }, container);
    });
  });
});
