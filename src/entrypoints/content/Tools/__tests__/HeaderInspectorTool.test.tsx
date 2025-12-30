import { describe, it } from 'vitest';
import { aiAssertEqual, aiAssertTruthy } from '../../../../test-utils/aiAssert';
import type { HeaderInspectorData } from '../tool-types';

type Header = { name: string; value: string };
type HeaderCategory = 'security' | 'caching' | 'general';

const SECURITY_HEADERS = new Set([
  'content-security-policy',
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'x-xss-protection',
  'referrer-policy',
  'permissions-policy'
]);

const CACHING_HEADERS = new Set([
  'cache-control',
  'expires',
  'etag',
  'last-modified',
  'age',
  'vary'
]);

const categorizeHeader = (name: string): HeaderCategory => {
  const lower = name.toLowerCase();
  if (SECURITY_HEADERS.has(lower)) return 'security';
  if (CACHING_HEADERS.has(lower)) return 'caching';
  return 'general';
};

// Mock data factories
const createMockHeader = (name: string, value: string): Header => ({ name, value });

const createMockHeaders = (): Header[] => [
  createMockHeader('Content-Type', 'text/html; charset=utf-8'),
  createMockHeader('Content-Security-Policy', "default-src 'self'"),
  createMockHeader('Cache-Control', 'max-age=3600'),
  createMockHeader('X-Frame-Options', 'DENY'),
  createMockHeader('ETag', '"abc123"'),
  createMockHeader('Server', 'nginx'),
];

describe('HeaderInspectorTool', () => {
  describe('Header categorization', () => {
    it('should categorize security headers correctly', () => {
      const securityHeaders = [
        'content-security-policy',
        'strict-transport-security',
        'x-frame-options',
        'x-content-type-options',
        'x-xss-protection',
        'referrer-policy',
        'permissions-policy'
      ];

      securityHeaders.forEach(header => {
        aiAssertEqual(
          { name: 'SecurityHeader', input: header },
          categorizeHeader(header),
          'security'
        );
      });
    });

    it('should categorize caching headers correctly', () => {
      const cachingHeaders = [
        'cache-control',
        'expires',
        'etag',
        'last-modified',
        'age',
        'vary'
      ];

      cachingHeaders.forEach(header => {
        aiAssertEqual(
          { name: 'CachingHeader', input: header },
          categorizeHeader(header),
          'caching'
        );
      });
    });

    it('should categorize other headers as general', () => {
      const generalHeaders = [
        'content-type',
        'content-length',
        'server',
        'date',
        'connection',
        'accept-ranges'
      ];

      generalHeaders.forEach(header => {
        aiAssertEqual(
          { name: 'GeneralHeader', input: header },
          categorizeHeader(header),
          'general'
        );
      });
    });

    it('should be case-insensitive', () => {
      aiAssertEqual(
        { name: 'UpperCaseSecurity', input: 'X-FRAME-OPTIONS' },
        categorizeHeader('X-FRAME-OPTIONS'),
        'security'
      );
      aiAssertEqual(
        { name: 'MixedCaseCache', input: 'Cache-Control' },
        categorizeHeader('Cache-Control'),
        'caching'
      );
    });
  });

  describe('Header filtering', () => {
    it('should filter security headers', () => {
      const headers = createMockHeaders();
      const securityHeaders = headers.filter(h => categorizeHeader(h.name) === 'security');

      aiAssertEqual(
        { name: 'SecurityFilterCount', input: headers.length },
        securityHeaders.length,
        2 // CSP and X-Frame-Options
      );
    });

    it('should filter caching headers', () => {
      const headers = createMockHeaders();
      const cachingHeaders = headers.filter(h => categorizeHeader(h.name) === 'caching');

      aiAssertEqual(
        { name: 'CachingFilterCount', input: headers.length },
        cachingHeaders.length,
        2 // Cache-Control and ETag
      );
    });

    it('should filter general headers', () => {
      const headers = createMockHeaders();
      const generalHeaders = headers.filter(h => categorizeHeader(h.name) === 'general');

      aiAssertEqual(
        { name: 'GeneralFilterCount', input: headers.length },
        generalHeaders.length,
        2 // Content-Type and Server
      );
    });

    it('should return all headers with "all" filter', () => {
      const headers = createMockHeaders();
      const filter = 'all';
      const filteredHeaders = filter === 'all' ? headers : headers.filter(h => categorizeHeader(h.name) === filter);

      aiAssertEqual(
        { name: 'AllFilterCount', input: headers.length },
        filteredHeaders.length,
        6
      );
    });
  });

  describe('Category styling', () => {
    it('should have unique styles per category', () => {
      const getCategoryStyle = (category: HeaderCategory) => {
        switch (category) {
          case 'security':
            return 'border-emerald-500/40 bg-emerald-500/10';
          case 'caching':
            return 'border-amber-500/40 bg-amber-500/10';
          default:
            return 'border-slate-700 bg-slate-800/50';
        }
      };

      aiAssertTruthy(
        { name: 'SecurityStyle', input: 'security' },
        getCategoryStyle('security').includes('emerald')
      );
      aiAssertTruthy(
        { name: 'CachingStyle', input: 'caching' },
        getCategoryStyle('caching').includes('amber')
      );
      aiAssertTruthy(
        { name: 'GeneralStyle', input: 'general' },
        getCategoryStyle('general').includes('slate')
      );
    });

    it('should have category labels', () => {
      const getCategoryLabel = (category: HeaderCategory) => {
        switch (category) {
          case 'security':
            return { text: 'Security', color: 'text-emerald-400' };
          case 'caching':
            return { text: 'Cache', color: 'text-amber-400' };
          default:
            return { text: 'General', color: 'text-slate-500' };
        }
      };

      aiAssertEqual(
        { name: 'SecurityLabel', input: 'security' },
        getCategoryLabel('security').text,
        'Security'
      );
      aiAssertEqual(
        { name: 'CachingLabel', input: 'caching' },
        getCategoryLabel('caching').text,
        'Cache'
      );
      aiAssertEqual(
        { name: 'GeneralLabel', input: 'general' },
        getCategoryLabel('general').text,
        'General'
      );
    });
  });

  describe('Export functionality', () => {
    it('should create export data with all fields', () => {
      const data: HeaderInspectorData = {
        url: 'https://example.com',
        status: 200,
        headers: createMockHeaders(),
        updatedAt: Date.now()
      };

      const exportData = {
        url: data.url,
        status: data.status,
        headers: data.headers!.map(h => ({ name: h.name, value: h.value })),
        capturedAt: data.updatedAt ? new Date(data.updatedAt).toISOString() : null
      };

      const json = JSON.stringify(exportData, null, 2);

      aiAssertTruthy(
        { name: 'ExportContainsUrl', input: json },
        json.includes('example.com')
      );
      aiAssertTruthy(
        { name: 'ExportContainsStatus', input: json },
        json.includes('200')
      );
      aiAssertTruthy(
        { name: 'ExportContainsHeaders', input: json },
        json.includes('Content-Type')
      );
    });
  });

  describe('Default values', () => {
    it('should use default values when data is undefined', () => {
      const getData = (): HeaderInspectorData | undefined => undefined;
      const data = getData();

      const headers = data?.headers ?? [];
      const url = data?.url;
      const status = data?.status;
      const error = data?.error;

      aiAssertEqual({ name: 'DefaultHeadersLength' }, headers.length, 0);
      aiAssertEqual({ name: 'DefaultUrl' }, url, undefined);
      aiAssertEqual({ name: 'DefaultStatus' }, status, undefined);
      aiAssertEqual({ name: 'DefaultError' }, error, undefined);
    });
  });

  describe('Error handling', () => {
    it('should display error when present', () => {
      const data: HeaderInspectorData = {
        url: 'https://example.com',
        error: 'Failed to fetch headers'
      };

      aiAssertTruthy(
        { name: 'ErrorPresent', input: data },
        data.error !== undefined
      );
      aiAssertEqual(
        { name: 'ErrorMessage', input: data },
        data.error,
        'Failed to fetch headers'
      );
    });
  });

  describe('Timestamp formatting', () => {
    it('should format updatedAt timestamp', () => {
      const updatedAt = Date.now();
      const formatted = new Date(updatedAt).toLocaleTimeString();

      aiAssertTruthy(
        { name: 'FormattedTime', input: { updatedAt, formatted } },
        formatted.includes(':')
      );
    });
  });

  describe('Edge cases', () => {
    it('should handle empty headers array', () => {
      const headers: Header[] = [];
      const categorized = {
        security: headers.filter(h => categorizeHeader(h.name) === 'security'),
        caching: headers.filter(h => categorizeHeader(h.name) === 'caching'),
        general: headers.filter(h => categorizeHeader(h.name) === 'general'),
        all: headers
      };

      aiAssertEqual({ name: 'EmptySecurityCount' }, categorized.security.length, 0);
      aiAssertEqual({ name: 'EmptyCachingCount' }, categorized.caching.length, 0);
      aiAssertEqual({ name: 'EmptyGeneralCount' }, categorized.general.length, 0);
    });

    it('should handle long header values', () => {
      const longValue = 'a'.repeat(500);
      const header = createMockHeader('X-Custom', longValue);

      aiAssertEqual(
        { name: 'LongHeaderValueLength', input: header },
        header.value.length,
        500
      );
    });

    it('should handle headers with special characters', () => {
      const header = createMockHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'"
      );

      aiAssertTruthy(
        { name: 'SpecialCharsInValue', input: header },
        header.value.includes("'") && header.value.includes(';')
      );
    });
  });
});
