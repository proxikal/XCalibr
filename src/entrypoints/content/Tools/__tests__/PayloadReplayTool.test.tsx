import React from 'react';
import { describe, it, beforeEach, afterEach, vi, expect } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { PayloadReplayTool } from '../PayloadReplayTool';
import type { PayloadReplayData } from '../tool-types';

const PayloadReplay = PayloadReplayTool.Component;

describe('PayloadReplayTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the PayloadReplay interface', () => {
      const onChange = vi.fn();
      const onSend = vi.fn(async () => {});
      const { container } = renderTool(
        <PayloadReplay data={undefined} onChange={onChange} onSend={onSend} />
      );

      aiAssertTruthy({ name: 'PayloadReplayRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'PayloadReplayHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const onSend = vi.fn(async () => {});
      const { container, findButton } = renderTool(
        <PayloadReplay data={undefined} onChange={onChange} onSend={onSend} />
      );

      const button = findButton('') || container.querySelector('button');
      aiAssertTruthy({ name: 'PayloadReplayInteractive' }, button);
    });

    it('displays send button', () => {
      const onChange = vi.fn();
      const onSend = vi.fn(async () => {});
      const { findButton } = renderTool(
        <PayloadReplay data={undefined} onChange={onChange} onSend={onSend} />
      );

      const sendBtn = findButton('Send Request');
      aiAssertTruthy({ name: 'SendButtonExists' }, sendBtn);
    });

    it('displays method buttons', () => {
      const onChange = vi.fn();
      const onSend = vi.fn(async () => {});
      const { findButton } = renderTool(
        <PayloadReplay data={undefined} onChange={onChange} onSend={onSend} />
      );

      expect(findButton('GET')).toBeTruthy();
      expect(findButton('POST')).toBeTruthy();
      expect(findButton('PUT')).toBeTruthy();
      expect(findButton('DELETE')).toBeTruthy();
      expect(findButton('PATCH')).toBeTruthy();
    });
  });

  describe('Session Options', () => {
    it('displays credentials toggle', () => {
      const onChange = vi.fn();
      const onSend = vi.fn(async () => {});
      const { container } = renderTool(
        <PayloadReplay data={undefined} onChange={onChange} onSend={onSend} />
      );

      expect(container.textContent).toContain('Include cookies/credentials');
    });

    it('displays follow redirects toggle', () => {
      const onChange = vi.fn();
      const onSend = vi.fn(async () => {});
      const { container } = renderTool(
        <PayloadReplay data={undefined} onChange={onChange} onSend={onSend} />
      );

      expect(container.textContent).toContain('Follow redirects');
    });

    it('displays raw request preview toggle', () => {
      const onChange = vi.fn();
      const onSend = vi.fn(async () => {});
      const { container } = renderTool(
        <PayloadReplay data={undefined} onChange={onChange} onSend={onSend} />
      );

      expect(container.textContent).toContain('Show raw request preview');
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const onSend = vi.fn(async () => {});
      const { container } = renderTool(
        <PayloadReplay data={undefined} onChange={onChange} onSend={onSend} />
      );

      aiAssertTruthy({ name: 'PayloadReplayInitialState' }, container);
    });

    it('displays URL input', () => {
      const onChange = vi.fn();
      const onSend = vi.fn(async () => {});
      const data: PayloadReplayData = {
        url: 'https://example.com/api'
      };
      const { container } = renderTool(
        <PayloadReplay data={data} onChange={onChange} onSend={onSend} />
      );

      const input = container.querySelector('input[type="text"]') as HTMLInputElement;
      expect(input?.value).toBe('https://example.com/api');
    });
  });

  describe('Response Display', () => {
    it('displays response status with color coding', () => {
      const onChange = vi.fn();
      const onSend = vi.fn(async () => {});
      const data: PayloadReplayData = {
        url: 'https://example.com/api',
        responseStatus: 200
      };
      const { container } = renderTool(
        <PayloadReplay data={data} onChange={onChange} onSend={onSend} />
      );

      expect(container.textContent).toContain('Status:');
      expect(container.textContent).toContain('200');
    });

    it('displays latency metrics', () => {
      const onChange = vi.fn();
      const onSend = vi.fn(async () => {});
      const data: PayloadReplayData = {
        url: 'https://example.com/api',
        responseStatus: 200,
        latencyMs: 150.5
      };
      const { container } = renderTool(
        <PayloadReplay data={data} onChange={onChange} onSend={onSend} />
      );

      expect(container.textContent).toContain('Latency:');
      expect(container.textContent).toContain('151ms');
    });

    it('displays request and response sizes', () => {
      const onChange = vi.fn();
      const onSend = vi.fn(async () => {});
      const data: PayloadReplayData = {
        url: 'https://example.com/api',
        responseStatus: 200,
        requestSize: 256,
        responseSize: 1024
      };
      const { container } = renderTool(
        <PayloadReplay data={data} onChange={onChange} onSend={onSend} />
      );

      expect(container.textContent).toContain('Req Size:');
      expect(container.textContent).toContain('Res Size:');
    });

    it('displays redirect info', () => {
      const onChange = vi.fn();
      const onSend = vi.fn(async () => {});
      const data: PayloadReplayData = {
        url: 'https://example.com/api',
        responseStatus: 200,
        redirectCount: 2,
        finalUrl: 'https://example.com/api/v2'
      };
      const { container } = renderTool(
        <PayloadReplay data={data} onChange={onChange} onSend={onSend} />
      );

      expect(container.textContent).toContain('Redirected 2x');
      expect(container.textContent).toContain('Final:');
    });
  });

  describe('Response View Modes', () => {
    it('displays view mode buttons', () => {
      const onChange = vi.fn();
      const onSend = vi.fn(async () => {});
      const data: PayloadReplayData = {
        url: 'https://example.com/api',
        responseStatus: 200,
        responseBody: '{"test": true}'
      };
      const { findButton } = renderTool(
        <PayloadReplay data={data} onChange={onChange} onSend={onSend} />
      );

      expect(findButton('Raw')).toBeTruthy();
      expect(findButton('JSON Tree')).toBeTruthy();
      expect(findButton('Headers')).toBeTruthy();
    });

    it('displays response headers in headers view', () => {
      const onChange = vi.fn();
      const onSend = vi.fn(async () => {});
      const data: PayloadReplayData = {
        url: 'https://example.com/api',
        responseStatus: 200,
        responseHeaders: [
          { name: 'Content-Type', value: 'application/json' }
        ],
        responseViewMode: 'headers'
      };
      const { container } = renderTool(
        <PayloadReplay data={data} onChange={onChange} onSend={onSend} />
      );

      expect(container.textContent).toContain('Content-Type');
      expect(container.textContent).toContain('application/json');
    });
  });

  describe('Error Handling', () => {
    it('displays error messages', () => {
      const onChange = vi.fn();
      const onSend = vi.fn(async () => {});
      const data: PayloadReplayData = {
        url: 'https://example.com/api',
        error: 'Network error occurred'
      };
      const { container } = renderTool(
        <PayloadReplay data={data} onChange={onChange} onSend={onSend} />
      );

      expect(container.textContent).toContain('Network error occurred');
    });
  });
});
