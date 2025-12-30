import { describe, it } from 'vitest';
import { aiAssertEqual } from '../../../../test-utils/aiAssert';
import { isValidPreviewUrl, isKnownBlockingSite, getPreviewFallbackMessage } from '../helpers';

describe('helpers', () => {
  describe('isValidPreviewUrl', () => {
    it('returns true for valid https URLs', () => {
      aiAssertEqual(
        { name: 'isValidPreviewUrl', input: 'https://example.com' },
        isValidPreviewUrl('https://example.com'),
        true
      );
    });

    it('returns true for valid http URLs', () => {
      aiAssertEqual(
        { name: 'isValidPreviewUrl', input: 'http://example.com' },
        isValidPreviewUrl('http://example.com'),
        true
      );
    });

    it('returns true for URLs with paths and query strings', () => {
      aiAssertEqual(
        { name: 'isValidPreviewUrl', input: 'https://example.com/path?query=1' },
        isValidPreviewUrl('https://example.com/path?query=1'),
        true
      );
    });

    it('returns false for javascript: URLs', () => {
      aiAssertEqual(
        { name: 'isValidPreviewUrl', input: 'javascript:void(0)' },
        isValidPreviewUrl('javascript:void(0)'),
        false
      );
    });

    it('returns false for mailto: URLs', () => {
      aiAssertEqual(
        { name: 'isValidPreviewUrl', input: 'mailto:test@example.com' },
        isValidPreviewUrl('mailto:test@example.com'),
        false
      );
    });

    it('returns false for tel: URLs', () => {
      aiAssertEqual(
        { name: 'isValidPreviewUrl', input: 'tel:+1234567890' },
        isValidPreviewUrl('tel:+1234567890'),
        false
      );
    });

    it('returns false for data: URLs', () => {
      aiAssertEqual(
        { name: 'isValidPreviewUrl', input: 'data:text/html,<h1>Test</h1>' },
        isValidPreviewUrl('data:text/html,<h1>Test</h1>'),
        false
      );
    });

    it('returns false for empty strings', () => {
      aiAssertEqual(
        { name: 'isValidPreviewUrl', input: '' },
        isValidPreviewUrl(''),
        false
      );
    });

    it('returns false for malformed URLs', () => {
      aiAssertEqual(
        { name: 'isValidPreviewUrl', input: 'not-a-url' },
        isValidPreviewUrl('not-a-url'),
        false
      );
    });

    it('returns false for file: URLs', () => {
      aiAssertEqual(
        { name: 'isValidPreviewUrl', input: 'file:///etc/passwd' },
        isValidPreviewUrl('file:///etc/passwd'),
        false
      );
    });
  });

  describe('isKnownBlockingSite', () => {
    it('returns true for x.com', () => {
      aiAssertEqual(
        { name: 'isKnownBlockingSite', input: 'https://x.com/user/status/123' },
        isKnownBlockingSite('https://x.com/user/status/123'),
        true
      );
    });

    it('returns true for twitter.com', () => {
      aiAssertEqual(
        { name: 'isKnownBlockingSite', input: 'https://twitter.com/user' },
        isKnownBlockingSite('https://twitter.com/user'),
        true
      );
    });

    it('returns true for google.com', () => {
      aiAssertEqual(
        { name: 'isKnownBlockingSite', input: 'https://www.google.com/search?q=test' },
        isKnownBlockingSite('https://www.google.com/search?q=test'),
        true
      );
    });

    it('returns true for facebook.com', () => {
      aiAssertEqual(
        { name: 'isKnownBlockingSite', input: 'https://www.facebook.com/page' },
        isKnownBlockingSite('https://www.facebook.com/page'),
        true
      );
    });

    it('returns true for instagram.com', () => {
      aiAssertEqual(
        { name: 'isKnownBlockingSite', input: 'https://www.instagram.com/user' },
        isKnownBlockingSite('https://www.instagram.com/user'),
        true
      );
    });

    it('returns false for regular sites', () => {
      aiAssertEqual(
        { name: 'isKnownBlockingSite', input: 'https://example.com' },
        isKnownBlockingSite('https://example.com'),
        false
      );
    });

    it('returns false for invalid URLs', () => {
      aiAssertEqual(
        { name: 'isKnownBlockingSite', input: 'not-a-url' },
        isKnownBlockingSite('not-a-url'),
        false
      );
    });
  });

  describe('getPreviewFallbackMessage', () => {
    it('returns blocking message for x.com', () => {
      const result = getPreviewFallbackMessage('https://x.com/user');
      aiAssertEqual(
        { name: 'getPreviewFallbackMessage', input: 'https://x.com/user' },
        result.includes('blocks'),
        true
      );
    });

    it('returns blocking message for google.com', () => {
      const result = getPreviewFallbackMessage('https://www.google.com/search');
      aiAssertEqual(
        { name: 'getPreviewFallbackMessage', input: 'https://www.google.com/search' },
        result.includes('blocks'),
        true
      );
    });

    it('returns generic message for unknown sites', () => {
      const result = getPreviewFallbackMessage('https://example.com');
      aiAssertEqual(
        { name: 'getPreviewFallbackMessage', input: 'https://example.com' },
        result.includes('Unable'),
        true
      );
    });
  });
});
