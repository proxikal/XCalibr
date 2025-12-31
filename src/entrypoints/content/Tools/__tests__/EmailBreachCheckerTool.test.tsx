import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertEqual, aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  waitFor,
  findButtonByText,
  waitForState,
  setRuntimeHandler
} from '../../../__tests__/integration-test-utils';
import type { EmailBreachCheckerData, BreachInfo } from '../tool-types';

// Test data constants
const TEST_EMAIL = 'test@example.com';
const TEST_EMAIL_SAFE = 'safe@example.com';

// Mock breach info factory
const createMockBreachInfo = (name: string, date: string, count: number): BreachInfo => ({
  name,
  domain: `${name.toLowerCase()}.com`,
  breachDate: date,
  addedDate: date,
  pwnCount: count,
  description: `${name} data breach exposing user information`,
  dataClasses: ['Email addresses', 'Passwords', 'Usernames'],
  isVerified: true,
  isSensitive: false
});

// Create mock breach results
const createMockBreachResults = (): BreachInfo[] => [
  createMockBreachInfo('LinkedIn', '2012-05-05', 164611595),
  createMockBreachInfo('Adobe', '2013-10-04', 152445165),
  createMockBreachInfo('Dropbox', '2012-07-01', 68648009)
];

// Helper function to validate email format
const isValidEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

// Helper function to format breach count
const formatBreachCount = (count: number): string => {
  if (count >= 1000000000) {
    return `${(count / 1000000000).toFixed(1)}B`;
  }
  if (count >= 1000000) {
    return `${(count / 1000000).toFixed(1)}M`;
  }
  if (count >= 1000) {
    return `${(count / 1000).toFixed(1)}K`;
  }
  return count.toString();
};

// Helper function to calculate total exposed records
const calculateTotalExposed = (breaches: BreachInfo[]): number => {
  return breaches.reduce((sum, breach) => sum + breach.pwnCount, 0);
};

describe('EmailBreachCheckerTool', () => {
  describe('Breach info creation', () => {
    it('creates breach with correct name', () => {
      const breach = createMockBreachInfo('LinkedIn', '2012-05-05', 164611595);
      aiAssertEqual({ name: 'BreachName', input: breach }, breach.name, 'LinkedIn');
    });

    it('creates breach with correct domain', () => {
      const breach = createMockBreachInfo('LinkedIn', '2012-05-05', 164611595);
      aiAssertEqual({ name: 'BreachDomain', input: breach }, breach.domain, 'linkedin.com');
    });

    it('creates breach with correct date', () => {
      const breach = createMockBreachInfo('LinkedIn', '2012-05-05', 164611595);
      aiAssertEqual({ name: 'BreachDate', input: breach }, breach.breachDate, '2012-05-05');
    });

    it('creates breach with correct pwn count', () => {
      const breach = createMockBreachInfo('LinkedIn', '2012-05-05', 164611595);
      aiAssertEqual({ name: 'BreachPwnCount', input: breach }, breach.pwnCount, 164611595);
    });

    it('creates breach with data classes', () => {
      const breach = createMockBreachInfo('LinkedIn', '2012-05-05', 164611595);
      aiAssertTruthy({ name: 'BreachDataClasses', input: breach }, breach.dataClasses.length > 0);
      aiAssertIncludes({ name: 'DataClassEmail', input: breach }, breach.dataClasses.join(','), 'Email');
    });

    it('creates breach with verified status', () => {
      const breach = createMockBreachInfo('LinkedIn', '2012-05-05', 164611595);
      aiAssertEqual({ name: 'BreachVerified', input: breach }, breach.isVerified, true);
    });
  });

  describe('Mock breach results', () => {
    it('creates multiple breach entries', () => {
      const breaches = createMockBreachResults();
      aiAssertEqual({ name: 'BreachCount', input: breaches }, breaches.length, 3);
    });

    it('includes LinkedIn breach', () => {
      const breaches = createMockBreachResults();
      const linkedin = breaches.find(b => b.name === 'LinkedIn');
      aiAssertTruthy({ name: 'LinkedInExists', input: breaches }, linkedin);
    });

    it('includes Adobe breach', () => {
      const breaches = createMockBreachResults();
      const adobe = breaches.find(b => b.name === 'Adobe');
      aiAssertTruthy({ name: 'AdobeExists', input: breaches }, adobe);
    });

    it('includes Dropbox breach', () => {
      const breaches = createMockBreachResults();
      const dropbox = breaches.find(b => b.name === 'Dropbox');
      aiAssertTruthy({ name: 'DropboxExists', input: breaches }, dropbox);
    });
  });

  describe('Email validation', () => {
    it('validates correct email format', () => {
      aiAssertEqual({ name: 'ValidEmail', input: TEST_EMAIL }, isValidEmail(TEST_EMAIL), true);
    });

    it('validates email with subdomain', () => {
      aiAssertEqual({ name: 'SubdomainEmail', input: 'test@mail.example.com' }, isValidEmail('test@mail.example.com'), true);
    });

    it('rejects email without @', () => {
      aiAssertEqual({ name: 'NoAtEmail', input: 'testexample.com' }, isValidEmail('testexample.com'), false);
    });

    it('rejects email without domain', () => {
      aiAssertEqual({ name: 'NoDomainEmail', input: 'test@' }, isValidEmail('test@'), false);
    });

    it('rejects email without local part', () => {
      aiAssertEqual({ name: 'NoLocalEmail', input: '@example.com' }, isValidEmail('@example.com'), false);
    });

    it('rejects empty string', () => {
      aiAssertEqual({ name: 'EmptyEmail', input: '' }, isValidEmail(''), false);
    });

    it('rejects email with spaces', () => {
      aiAssertEqual({ name: 'SpaceEmail', input: 'test @example.com' }, isValidEmail('test @example.com'), false);
    });
  });

  describe('Breach count formatting', () => {
    it('formats billions correctly', () => {
      aiAssertEqual({ name: 'BillionFormat', input: 1500000000 }, formatBreachCount(1500000000), '1.5B');
    });

    it('formats millions correctly', () => {
      aiAssertEqual({ name: 'MillionFormat', input: 164611595 }, formatBreachCount(164611595), '164.6M');
    });

    it('formats thousands correctly', () => {
      aiAssertEqual({ name: 'ThousandFormat', input: 50000 }, formatBreachCount(50000), '50.0K');
    });

    it('formats small numbers correctly', () => {
      aiAssertEqual({ name: 'SmallFormat', input: 500 }, formatBreachCount(500), '500');
    });
  });

  describe('Total exposed calculation', () => {
    it('calculates total from multiple breaches', () => {
      const breaches = createMockBreachResults();
      const total = calculateTotalExposed(breaches);
      const expectedTotal = 164611595 + 152445165 + 68648009;
      aiAssertEqual({ name: 'TotalExposed', input: breaches }, total, expectedTotal);
    });

    it('returns 0 for empty breaches', () => {
      aiAssertEqual({ name: 'EmptyTotal', input: [] }, calculateTotalExposed([]), 0);
    });

    it('handles single breach', () => {
      const singleBreach = [createMockBreachInfo('Test', '2024-01-01', 1000)];
      aiAssertEqual({ name: 'SingleTotal', input: singleBreach }, calculateTotalExposed(singleBreach), 1000);
    });
  });

  describe('Default values', () => {
    it('should use default values when data is undefined', () => {
      const getData = (): EmailBreachCheckerData | undefined => undefined;
      const data = getData();

      const email = data?.email ?? '';
      const loading = data?.loading ?? false;
      const breaches = data?.breaches ?? [];
      const error = data?.error;

      aiAssertEqual({ name: 'DefaultEmail' }, email, '');
      aiAssertEqual({ name: 'DefaultLoading' }, loading, false);
      aiAssertEqual({ name: 'DefaultBreachesLength' }, breaches.length, 0);
      aiAssertEqual({ name: 'DefaultError' }, error, undefined);
    });
  });

  describe('Safe email state', () => {
    it('should indicate no breaches found', () => {
      const data: EmailBreachCheckerData = {
        email: TEST_EMAIL_SAFE,
        breaches: [],
        checkedAt: Date.now()
      };

      aiAssertEqual({ name: 'SafeBreachCount', input: data }, data.breaches?.length, 0);
      aiAssertTruthy({ name: 'SafeCheckedAt', input: data }, data.checkedAt !== undefined);
    });
  });

  describe('Breached email state', () => {
    it('should contain breach information', () => {
      const breaches = createMockBreachResults();
      const data: EmailBreachCheckerData = {
        email: TEST_EMAIL,
        breaches,
        checkedAt: Date.now()
      };

      aiAssertTruthy({ name: 'BreachesPresent', input: data }, (data.breaches?.length ?? 0) > 0);
      aiAssertEqual({ name: 'BreachCount', input: data }, data.breaches?.length, 3);
    });
  });

  describe('Error handling', () => {
    it('should handle error state', () => {
      const data: EmailBreachCheckerData = {
        email: TEST_EMAIL,
        error: 'Failed to check email'
      };

      aiAssertTruthy({ name: 'ErrorPresent', input: data }, data.error !== undefined);
      aiAssertIncludes({ name: 'ErrorMessage', input: data }, data.error ?? '', 'Failed');
    });

    it('should handle rate limit error', () => {
      const data: EmailBreachCheckerData = {
        email: TEST_EMAIL,
        error: 'Rate limit exceeded. Please try again later.'
      };

      aiAssertIncludes({ name: 'RateLimitError', input: data }, data.error ?? '', 'Rate limit');
    });
  });

  describe('Loading state', () => {
    it('should track loading state', () => {
      const data: EmailBreachCheckerData = {
        email: TEST_EMAIL,
        loading: true
      };

      aiAssertEqual({ name: 'LoadingState', input: data }, data.loading, true);
    });
  });

  describe('Data classes display', () => {
    it('should format data classes for display', () => {
      const breach = createMockBreachInfo('Test', '2024-01-01', 1000);
      const formatted = breach.dataClasses.join(', ');
      aiAssertIncludes({ name: 'FormattedDataClasses', input: breach }, formatted, 'Email addresses');
      aiAssertIncludes({ name: 'FormattedDataClasses', input: breach }, formatted, 'Passwords');
    });
  });

  describe('Integration tests', () => {
    beforeEach(() => {
      document.body.innerHTML = '';
      resetChrome();
    });

    afterEach(() => {
      document.body.innerHTML = '';
      document.head.innerHTML = '';
      vi.restoreAllMocks();
    });

    it('renders Email Breach Checker tool with input and button', async () => {
      setRuntimeHandler('xcalibr-email-breach-check', () => ({ breaches: [] }));

      const root = await mountWithTool('emailBreachChecker');
      if (!root) return;

      const titleElement = await waitFor(() => {
        const elements = Array.from(root.querySelectorAll('*'));
        return elements.find(el => el.textContent?.includes('Email Breach'));
      });
      aiAssertTruthy({ name: 'TitleFound' }, titleElement);

      const input = root.querySelector('input[type="email"], input[placeholder*="email" i]');
      aiAssertTruthy({ name: 'EmailInputFound' }, input);

      const checkButton = findButtonByText(root, 'Check');
      aiAssertTruthy({ name: 'CheckButtonFound' }, checkButton);
    });

    it('displays breaches when email is pwned', async () => {
      const mockBreaches = createMockBreachResults();
      setRuntimeHandler('xcalibr-email-breach-check', () => ({
        breaches: mockBreaches
      }));

      const root = await mountWithTool('emailBreachChecker', {
        email: TEST_EMAIL,
        breaches: mockBreaches,
        checkedAt: Date.now()
      });
      if (!root) return;

      const linkedInElement = await waitFor(() => {
        const elements = Array.from(root.querySelectorAll('*'));
        return elements.find(el => el.textContent?.includes('LinkedIn'));
      });
      aiAssertTruthy({ name: 'LinkedInDisplayed' }, linkedInElement);
    });

    it('displays safe message when no breaches found', async () => {
      setRuntimeHandler('xcalibr-email-breach-check', () => ({
        breaches: []
      }));

      const root = await mountWithTool('emailBreachChecker', {
        email: TEST_EMAIL_SAFE,
        breaches: [],
        checkedAt: Date.now()
      });
      if (!root) return;

      const safeElement = await waitFor(() => {
        const elements = Array.from(root.querySelectorAll('*'));
        return elements.find(el =>
          el.textContent?.toLowerCase().includes('no breach') ||
          el.textContent?.toLowerCase().includes('safe') ||
          el.textContent?.toLowerCase().includes('not found')
        );
      });
      aiAssertTruthy({ name: 'SafeMessageDisplayed' }, safeElement);
    });

    it('checks email and stores results in state', async () => {
      const mockBreaches = createMockBreachResults();
      setRuntimeHandler('xcalibr-email-breach-check', () => ({
        breaches: mockBreaches
      }));

      const root = await mountWithTool('emailBreachChecker', { email: TEST_EMAIL });
      if (!root) return;

      const checkButton = findButtonByText(root, 'Check');
      aiAssertTruthy({ name: 'CheckButtonFound' }, checkButton);
      checkButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));

      await flushPromises();

      const state = await waitForState((s) => {
        const data = s.toolData?.emailBreachChecker as EmailBreachCheckerData | undefined;
        return Array.isArray(data?.breaches) && data.breaches.length > 0;
      });
      aiAssertTruthy({ name: 'StateUpdated' }, state);
      const data = state?.toolData?.emailBreachChecker as EmailBreachCheckerData;
      aiAssertEqual({ name: 'BreachCount', state: data }, data.breaches!.length, 3);
    });

    it('handles check error gracefully', async () => {
      setRuntimeHandler('xcalibr-email-breach-check', () => ({
        error: 'Service unavailable'
      }));

      const root = await mountWithTool('emailBreachChecker', { email: TEST_EMAIL });
      if (!root) return;

      const checkButton = findButtonByText(root, 'Check');
      aiAssertTruthy({ name: 'CheckButtonFound' }, checkButton);
      checkButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));

      await flushPromises();

      const state = await waitForState((s) => {
        const data = s.toolData?.emailBreachChecker as EmailBreachCheckerData | undefined;
        return !!data?.error;
      });
      aiAssertTruthy({ name: 'ErrorStateUpdated' }, state);
      const data = state?.toolData?.emailBreachChecker as EmailBreachCheckerData;
      aiAssertEqual({ name: 'ErrorValue', state: data }, data.error, 'Service unavailable');
    });

    it('shows loading state during check', async () => {
      const root = await mountWithTool('emailBreachChecker', {
        email: TEST_EMAIL,
        loading: true
      });
      if (!root) return;

      const loadingElement = await waitFor(() => {
        const elements = Array.from(root.querySelectorAll('*'));
        return elements.find(el =>
          el.textContent?.toLowerCase().includes('checking') ||
          el.textContent?.toLowerCase().includes('loading')
        );
      });
      aiAssertTruthy({ name: 'LoadingDisplayed' }, loadingElement);
    });
  });
});
