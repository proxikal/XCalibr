import React from 'react';
import { describe, it, beforeEach, afterEach, vi, expect } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { RequestLogTool } from '../RequestLogTool';
import type { RequestLogData, RequestLogEntry } from '../tool-types';

const RequestLog = RequestLogTool.Component;

const createMockEntries = (): RequestLogEntry[] => [
  {
    name: 'https://example.com/api/data.json',
    initiatorType: 'fetch',
    duration: 150,
    transferSize: 5000,
    startTime: 100,
    responseStatus: 200,
    domainLookupStart: 100,
    domainLookupEnd: 110,
    connectStart: 110,
    connectEnd: 130,
    requestStart: 130,
    responseStart: 180,
    responseEnd: 250,
    decodedBodySize: 5000
  },
  {
    name: 'https://cdn.example.com/script.js',
    initiatorType: 'script',
    duration: 250,
    transferSize: 0,
    startTime: 50,
    responseStatus: 200,
    decodedBodySize: 15000,
    isCached: true
  },
  {
    name: 'https://example.com/image.png',
    initiatorType: 'img',
    duration: 1500,
    transferSize: 50000,
    startTime: 200,
    responseStatus: 200
  },
  {
    name: 'https://example.com/redirect',
    initiatorType: 'fetch',
    duration: 300,
    transferSize: 0,
    startTime: 300,
    responseStatus: 302,
    isRedirect: true
  },
  {
    name: 'https://example.com/error',
    initiatorType: 'fetch',
    duration: 100,
    transferSize: 0,
    startTime: 400,
    responseStatus: 404
  }
];

describe('RequestLogTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the RequestLog interface', () => {
      const onChange = vi.fn();
      const onClear = vi.fn(async () => {});
      const { container } = renderTool(
        <RequestLog data={undefined} onChange={onChange} onClear={onClear} />
      );

      aiAssertTruthy({ name: 'RequestLogRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'RequestLogHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const onClear = vi.fn(async () => {});
      const { container, findButton } = renderTool(
        <RequestLog data={undefined} onChange={onChange} onClear={onClear} />
      );

      const button = findButton('') || container.querySelector('button');
      aiAssertTruthy({ name: 'RequestLogInteractive' }, button);
    });

    it('displays clear button', () => {
      const onChange = vi.fn();
      const onClear = vi.fn(async () => {});
      const { findButton } = renderTool(
        <RequestLog data={undefined} onChange={onChange} onClear={onClear} />
      );

      const clearBtn = findButton('Clear');
      aiAssertTruthy({ name: 'ClearButtonExists' }, clearBtn);
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const onClear = vi.fn(async () => {});
      const { container } = renderTool(
        <RequestLog data={undefined} onChange={onChange} onClear={onClear} />
      );

      aiAssertTruthy({ name: 'RequestLogInitialState' }, container);
      expect(container.textContent).toContain('0 request');
    });

    it('displays entries when data is provided', () => {
      const onChange = vi.fn();
      const onClear = vi.fn(async () => {});
      const data: RequestLogData = {
        entries: createMockEntries()
      };
      const { container } = renderTool(
        <RequestLog data={data} onChange={onChange} onClear={onClear} />
      );

      expect(container.textContent).toContain('5 request');
    });
  });

  describe('Badges', () => {
    it('displays cached badge for cached entries', () => {
      const onChange = vi.fn();
      const onClear = vi.fn(async () => {});
      const data: RequestLogData = {
        entries: createMockEntries()
      };
      const { container } = renderTool(
        <RequestLog data={data} onChange={onChange} onClear={onClear} />
      );

      expect(container.textContent).toContain('cached');
    });

    it('displays redirect badge for redirect responses', () => {
      const onChange = vi.fn();
      const onClear = vi.fn(async () => {});
      const data: RequestLogData = {
        entries: createMockEntries()
      };
      const { container } = renderTool(
        <RequestLog data={data} onChange={onChange} onClear={onClear} />
      );

      expect(container.textContent).toContain('redirect');
    });

    it('displays error badge for error responses', () => {
      const onChange = vi.fn();
      const onClear = vi.fn(async () => {});
      const data: RequestLogData = {
        entries: createMockEntries()
      };
      const { container } = renderTool(
        <RequestLog data={data} onChange={onChange} onClear={onClear} />
      );

      expect(container.textContent).toContain('error');
    });

    it('displays slow badge for slow requests', () => {
      const onChange = vi.fn();
      const onClear = vi.fn(async () => {});
      const data: RequestLogData = {
        entries: createMockEntries()
      };
      const { container } = renderTool(
        <RequestLog data={data} onChange={onChange} onClear={onClear} />
      );

      expect(container.textContent).toContain('slow');
    });
  });

  describe('Filtering', () => {
    it('shows filter buttons for available types', () => {
      const onChange = vi.fn();
      const onClear = vi.fn(async () => {});
      const data: RequestLogData = {
        entries: createMockEntries()
      };
      const { findButton } = renderTool(
        <RequestLog data={data} onChange={onChange} onClear={onClear} />
      );

      expect(findButton('All')).toBeTruthy();
      expect(findButton('fetch')).toBeTruthy();
      expect(findButton('script')).toBeTruthy();
      expect(findButton('img')).toBeTruthy();
    });
  });

  describe('Waterfall Chart', () => {
    it('renders waterfall bars for entries', () => {
      const onChange = vi.fn();
      const onClear = vi.fn(async () => {});
      const data: RequestLogData = {
        entries: createMockEntries()
      };
      const { container } = renderTool(
        <RequestLog data={data} onChange={onChange} onClear={onClear} />
      );

      // Check for waterfall bar elements (bg-slate-800 is the background)
      const waterfallBars = container.querySelectorAll('.bg-slate-800.rounded');
      expect(waterfallBars.length).toBeGreaterThan(0);
    });
  });

  describe('Export', () => {
    it('shows export buttons when entries exist', () => {
      const onChange = vi.fn();
      const onClear = vi.fn(async () => {});
      const data: RequestLogData = {
        entries: createMockEntries()
      };
      const { findButton } = renderTool(
        <RequestLog data={data} onChange={onChange} onClear={onClear} />
      );

      expect(findButton('Save as Text')).toBeTruthy();
      expect(findButton('Save as JSON')).toBeTruthy();
    });
  });
});
