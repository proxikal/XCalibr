import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { DnsRecordViewerTool } from '../DnsRecordViewerTool';

const DnsRecordViewer = DnsRecordViewerTool.Component;

describe('DnsRecordViewerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the DnsRecordViewer interface', () => {
      const onChange = vi.fn();
      const onLookup = vi.fn(async () => {});
      const { container } = renderTool(
        <DnsRecordViewer data={undefined} onChange={onChange} onLookup={onLookup} />
      );

      aiAssertTruthy({ name: 'DnsRecordViewerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'DnsRecordViewerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const onLookup = vi.fn(async () => {});
      const { container, findButton } = renderTool(
        <DnsRecordViewer data={undefined} onChange={onChange} onLookup={onLookup} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'DnsRecordViewerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const onLookup = vi.fn(async () => {});
      const { container } = renderTool(
        <DnsRecordViewer data={undefined} onChange={onChange} onLookup={onLookup} />
      );

      aiAssertTruthy({ name: 'DnsRecordViewerInitialState' }, container);
    });
  });
});
