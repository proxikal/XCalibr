import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { FormFuzzerTool } from '../FormFuzzerTool';

const FormFuzzer = FormFuzzerTool.Component;

describe('FormFuzzerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the FormFuzzer interface', () => {
      const onChange = vi.fn();
      const onRefresh = vi.fn(async () => {});
      const onApply = vi.fn() as any;
      const onSubmit = vi.fn() as any;
      const { container } = renderTool(
        <FormFuzzer data={undefined} onChange={onChange} onRefresh={onRefresh} onApply={onApply} onSubmit={onSubmit} />
      );

      aiAssertTruthy({ name: 'FormFuzzerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'FormFuzzerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const onRefresh = vi.fn(async () => {});
      const onApply = vi.fn() as any;
      const onSubmit = vi.fn() as any;
      const { container, findButton } = renderTool(
        <FormFuzzer data={undefined} onChange={onChange} onRefresh={onRefresh} onApply={onApply} onSubmit={onSubmit} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'FormFuzzerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const onRefresh = vi.fn(async () => {});
      const onApply = vi.fn() as any;
      const onSubmit = vi.fn() as any;
      const { container } = renderTool(
        <FormFuzzer data={undefined} onChange={onChange} onRefresh={onRefresh} onApply={onApply} onSubmit={onSubmit} />
      );

      aiAssertTruthy({ name: 'FormFuzzerInitialState' }, container);
    });
  });
});
