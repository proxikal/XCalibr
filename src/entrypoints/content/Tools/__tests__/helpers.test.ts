import { describe, it } from 'vitest';
import { aiAssertEqual } from '../../../../test-utils/aiAssert';
import { isValidPreviewUrl } from '../helpers';

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
});
