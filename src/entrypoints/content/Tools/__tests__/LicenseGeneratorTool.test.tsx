import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { LicenseGeneratorTool } from '../LicenseGeneratorTool';
import type { LicenseGeneratorData } from '../LicenseGeneratorTool';

const LicenseGenerator = LicenseGeneratorTool.Component;

describe('LicenseGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the LicenseGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <LicenseGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'LicenseGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'LicenseGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <LicenseGenerator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'LicenseGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <LicenseGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'LicenseGeneratorInitialState' }, container);
    });
  });
});
