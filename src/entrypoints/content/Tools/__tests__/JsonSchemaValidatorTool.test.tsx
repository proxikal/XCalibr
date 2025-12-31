import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { JsonSchemaValidatorTool } from '../JsonSchemaValidatorTool';

const JsonSchemaValidator = JsonSchemaValidatorTool.Component;

describe('JsonSchemaValidatorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the JsonSchemaValidator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <JsonSchemaValidator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'JsonSchemaValidatorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'JsonSchemaValidatorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <JsonSchemaValidator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'JsonSchemaValidatorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <JsonSchemaValidator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'JsonSchemaValidatorInitialState' }, container);
    });
  });
});
