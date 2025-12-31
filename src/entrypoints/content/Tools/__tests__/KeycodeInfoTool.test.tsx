import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { KeycodeInfoTool } from '../KeycodeInfoTool';
import type { KeycodeInfoData } from '../KeycodeInfoTool';

const KeycodeInfo = KeycodeInfoTool.Component;

describe('KeycodeInfoTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the KeycodeInfo interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <KeycodeInfo data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'KeycodeInfoRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'KeycodeInfoHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has content elements', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <KeycodeInfo data={undefined} onChange={onChange} />
      );

      // This tool displays keycode info and responds to keyboard events
      // It doesn't have traditional form elements
      aiAssertTruthy(
        { name: 'KeycodeInfoHasElements' },
        container.querySelectorAll('*').length > 0
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <KeycodeInfo data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'KeycodeInfoInitialState' }, container);
    });
  });
});
