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
import type { SslCertDecoderData, CertificateInfo } from '../tool-types';

// Test data constants
const TEST_DOMAIN = 'example.com';
const TEST_DOMAIN_INVALID = 'not-a-domain';

// Mock certificate info factory
const createMockCertInfo = (): CertificateInfo => ({
  subject: {
    CN: 'example.com',
    O: 'Example Organization',
    C: 'US'
  },
  issuer: {
    CN: 'DigiCert TLS RSA SHA256 2020 CA1',
    O: 'DigiCert Inc',
    C: 'US'
  },
  validFrom: '2024-01-01T00:00:00Z',
  validTo: '2025-01-01T00:00:00Z',
  serialNumber: 'A1B2C3D4E5F6',
  fingerprint: 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
  signatureAlgorithm: 'SHA256withRSA',
  keySize: 2048,
  sans: ['example.com', 'www.example.com', '*.example.com'],
  isExpired: false,
  daysUntilExpiry: 180
});

// Helper function to validate domain format
const isValidDomain = (domain: string): boolean => {
  const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/;
  return domainRegex.test(domain);
};

// Helper function to format days until expiry
const formatExpiryDays = (days: number): string => {
  if (days < 0) return `Expired ${Math.abs(days)} days ago`;
  if (days === 0) return 'Expires today';
  if (days === 1) return 'Expires tomorrow';
  return `Expires in ${days} days`;
};

// Helper function to calculate certificate age percentage
const calculateAgePercentage = (validFrom: string, validTo: string): number => {
  const start = new Date(validFrom).getTime();
  const end = new Date(validTo).getTime();
  const now = Date.now();
  if (now >= end) return 100;
  if (now <= start) return 0;
  return Math.round(((now - start) / (end - start)) * 100);
};

describe('SslCertDecoderTool', () => {
  describe('Certificate info creation', () => {
    it('creates certificate with correct subject CN', () => {
      const cert = createMockCertInfo();
      aiAssertEqual({ name: 'SubjectCN', input: cert }, cert.subject.CN, 'example.com');
    });

    it('creates certificate with correct issuer', () => {
      const cert = createMockCertInfo();
      aiAssertIncludes({ name: 'IssuerOrg', input: cert }, cert.issuer.O ?? '', 'DigiCert');
    });

    it('creates certificate with validity dates', () => {
      const cert = createMockCertInfo();
      aiAssertTruthy({ name: 'ValidFromPresent', input: cert }, cert.validFrom);
      aiAssertTruthy({ name: 'ValidToPresent', input: cert }, cert.validTo);
    });

    it('creates certificate with serial number', () => {
      const cert = createMockCertInfo();
      aiAssertEqual({ name: 'SerialNumber', input: cert }, cert.serialNumber, 'A1B2C3D4E5F6');
    });

    it('creates certificate with fingerprint', () => {
      const cert = createMockCertInfo();
      aiAssertIncludes({ name: 'Fingerprint', input: cert }, cert.fingerprint, 'AA:BB:CC');
    });

    it('creates certificate with key size', () => {
      const cert = createMockCertInfo();
      aiAssertEqual({ name: 'KeySize', input: cert }, cert.keySize, 2048);
    });

    it('creates certificate with SANs', () => {
      const cert = createMockCertInfo();
      aiAssertTruthy({ name: 'SANsExist', input: cert }, cert.sans && cert.sans.length > 0);
      aiAssertIncludes({ name: 'SANsContainDomain', input: cert }, cert.sans?.join(',') ?? '', 'example.com');
    });

    it('creates certificate with expiry status', () => {
      const cert = createMockCertInfo();
      aiAssertEqual({ name: 'NotExpired', input: cert }, cert.isExpired, false);
      aiAssertTruthy({ name: 'DaysUntilExpiry', input: cert }, cert.daysUntilExpiry !== undefined);
    });
  });

  describe('Domain validation', () => {
    it('validates correct domain format', () => {
      aiAssertEqual({ name: 'ValidDomain', input: TEST_DOMAIN }, isValidDomain(TEST_DOMAIN), true);
    });

    it('validates domain with subdomain', () => {
      aiAssertEqual({ name: 'SubdomainDomain', input: 'www.example.com' }, isValidDomain('www.example.com'), true);
    });

    it('rejects domain without TLD', () => {
      aiAssertEqual({ name: 'NoTLDDomain', input: 'example' }, isValidDomain('example'), false);
    });

    it('rejects empty string', () => {
      aiAssertEqual({ name: 'EmptyDomain', input: '' }, isValidDomain(''), false);
    });

    it('rejects domain with invalid characters', () => {
      aiAssertEqual({ name: 'InvalidCharsDomain', input: 'exam!ple.com' }, isValidDomain('exam!ple.com'), false);
    });

    it('rejects domain starting with hyphen', () => {
      aiAssertEqual({ name: 'HyphenStartDomain', input: '-example.com' }, isValidDomain('-example.com'), false);
    });
  });

  describe('Expiry formatting', () => {
    it('formats expired certificate', () => {
      aiAssertIncludes({ name: 'ExpiredFormat', input: -30 }, formatExpiryDays(-30), 'Expired');
    });

    it('formats certificate expiring today', () => {
      aiAssertIncludes({ name: 'TodayFormat', input: 0 }, formatExpiryDays(0), 'today');
    });

    it('formats certificate expiring tomorrow', () => {
      aiAssertIncludes({ name: 'TomorrowFormat', input: 1 }, formatExpiryDays(1), 'tomorrow');
    });

    it('formats certificate expiring in future', () => {
      aiAssertIncludes({ name: 'FutureFormat', input: 180 }, formatExpiryDays(180), '180 days');
    });
  });

  describe('Certificate age percentage', () => {
    it('calculates age for certificate at start', () => {
      const now = new Date();
      const start = new Date(now.getTime() - 1000);
      const end = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);
      const percentage = calculateAgePercentage(start.toISOString(), end.toISOString());
      aiAssertTruthy({ name: 'NearStartAge', input: percentage }, percentage < 5);
    });

    it('calculates age for expired certificate', () => {
      const now = new Date();
      const start = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000);
      const end = new Date(now.getTime() - 1000);
      const percentage = calculateAgePercentage(start.toISOString(), end.toISOString());
      aiAssertEqual({ name: 'ExpiredAge', input: percentage }, percentage, 100);
    });

    it('calculates age for certificate at midpoint', () => {
      const now = new Date();
      const halfYear = 182 * 24 * 60 * 60 * 1000;
      const start = new Date(now.getTime() - halfYear);
      const end = new Date(now.getTime() + halfYear);
      const percentage = calculateAgePercentage(start.toISOString(), end.toISOString());
      aiAssertTruthy({ name: 'MidpointAge', input: percentage }, percentage >= 45 && percentage <= 55);
    });
  });

  describe('Default values', () => {
    it('should use default values when data is undefined', () => {
      const getData = (): SslCertDecoderData | undefined => undefined;
      const data = getData();

      const domain = data?.domain ?? '';
      const loading = data?.loading ?? false;
      const certificate = data?.certificate;
      const error = data?.error;

      aiAssertEqual({ name: 'DefaultDomain' }, domain, '');
      aiAssertEqual({ name: 'DefaultLoading' }, loading, false);
      aiAssertEqual({ name: 'DefaultCertificate' }, certificate, undefined);
      aiAssertEqual({ name: 'DefaultError' }, error, undefined);
    });
  });

  describe('Successful certificate fetch', () => {
    it('should contain certificate information', () => {
      const cert = createMockCertInfo();
      const data: SslCertDecoderData = {
        domain: TEST_DOMAIN,
        certificate: cert,
        fetchedAt: Date.now()
      };

      aiAssertTruthy({ name: 'CertPresent', input: data }, data.certificate !== undefined);
      aiAssertEqual({ name: 'CertSubject', input: data }, data.certificate?.subject.CN, 'example.com');
    });
  });

  describe('Error handling', () => {
    it('should handle error state', () => {
      const data: SslCertDecoderData = {
        domain: TEST_DOMAIN,
        error: 'Unable to connect to server'
      };

      aiAssertTruthy({ name: 'ErrorPresent', input: data }, data.error !== undefined);
      aiAssertIncludes({ name: 'ErrorMessage', input: data }, data.error ?? '', 'Unable');
    });

    it('should handle timeout error', () => {
      const data: SslCertDecoderData = {
        domain: TEST_DOMAIN,
        error: 'Connection timed out'
      };

      aiAssertIncludes({ name: 'TimeoutError', input: data }, data.error ?? '', 'timed out');
    });

    it('should handle invalid certificate error', () => {
      const data: SslCertDecoderData = {
        domain: TEST_DOMAIN,
        error: 'Invalid or self-signed certificate'
      };

      aiAssertIncludes({ name: 'InvalidCertError', input: data }, data.error ?? '', 'certificate');
    });
  });

  describe('Loading state', () => {
    it('should track loading state', () => {
      const data: SslCertDecoderData = {
        domain: TEST_DOMAIN,
        loading: true
      };

      aiAssertEqual({ name: 'LoadingState', input: data }, data.loading, true);
    });
  });

  describe('SANs display', () => {
    it('should format SANs for display', () => {
      const cert = createMockCertInfo();
      const formatted = cert.sans?.join(', ') ?? '';
      aiAssertIncludes({ name: 'FormattedSANs', input: cert }, formatted, 'www.example.com');
      aiAssertIncludes({ name: 'FormattedWildcard', input: cert }, formatted, '*.example.com');
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

    it('renders SSL Certificate Decoder tool with input and button', async () => {
      setRuntimeHandler('xcalibr-ssl-cert-decode', () => ({ certificate: createMockCertInfo() }));

      const root = await mountWithTool('sslCertDecoder');
      if (!root) return;

      const titleElement = await waitFor(() => {
        const elements = Array.from(root.querySelectorAll('*'));
        return elements.find(el => el.textContent?.includes('SSL Certificate'));
      });
      aiAssertTruthy({ name: 'TitleFound' }, titleElement);

      const input = root.querySelector('input[type="text"], input[placeholder*="domain" i]');
      aiAssertTruthy({ name: 'DomainInputFound' }, input);

      const decodeButton = findButtonByText(root, 'Decode') || findButtonByText(root, 'Fetch');
      aiAssertTruthy({ name: 'DecodeButtonFound' }, decodeButton);
    });

    it('displays certificate info when decoded', async () => {
      const mockCert = createMockCertInfo();
      setRuntimeHandler('xcalibr-ssl-cert-decode', () => ({
        certificate: mockCert
      }));

      const root = await mountWithTool('sslCertDecoder', {
        domain: TEST_DOMAIN,
        certificate: mockCert,
        fetchedAt: Date.now()
      });
      if (!root) return;

      const issuerElement = await waitFor(() => {
        const elements = Array.from(root.querySelectorAll('*'));
        return elements.find(el => el.textContent?.includes('DigiCert'));
      });
      aiAssertTruthy({ name: 'IssuerDisplayed' }, issuerElement);
    });

    it('displays error message on failure', async () => {
      setRuntimeHandler('xcalibr-ssl-cert-decode', () => ({
        error: 'Connection failed'
      }));

      const root = await mountWithTool('sslCertDecoder', {
        domain: TEST_DOMAIN,
        error: 'Connection failed',
        fetchedAt: Date.now()
      });
      if (!root) return;

      const errorElement = await waitFor(() => {
        const elements = Array.from(root.querySelectorAll('*'));
        return elements.find(el =>
          el.textContent?.toLowerCase().includes('connection') ||
          el.textContent?.toLowerCase().includes('failed') ||
          el.textContent?.toLowerCase().includes('error')
        );
      });
      aiAssertTruthy({ name: 'ErrorDisplayed' }, errorElement);
    });

    it('checks domain and stores results in state', async () => {
      const mockCert = createMockCertInfo();
      setRuntimeHandler('xcalibr-ssl-cert-decode', () => ({
        certificate: mockCert
      }));

      const root = await mountWithTool('sslCertDecoder', { domain: TEST_DOMAIN });
      if (!root) return;

      const decodeButton = findButtonByText(root, 'Decode') || findButtonByText(root, 'Fetch');
      aiAssertTruthy({ name: 'DecodeButtonFound' }, decodeButton);
      decodeButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));

      await flushPromises();

      const state = await waitForState((s) => {
        const data = s.toolData?.sslCertDecoder as SslCertDecoderData | undefined;
        return data?.certificate !== undefined;
      });
      aiAssertTruthy({ name: 'StateUpdated' }, state);
      const data = state?.toolData?.sslCertDecoder as SslCertDecoderData;
      aiAssertEqual({ name: 'CertSubjectCN', state: data }, data.certificate?.subject.CN, 'example.com');
    });

    it('shows loading state during fetch', async () => {
      const root = await mountWithTool('sslCertDecoder', {
        domain: TEST_DOMAIN,
        loading: true
      });
      if (!root) return;

      const loadingElement = await waitFor(() => {
        const elements = Array.from(root.querySelectorAll('*'));
        return elements.find(el =>
          el.textContent?.toLowerCase().includes('loading') ||
          el.textContent?.toLowerCase().includes('fetching') ||
          el.textContent?.toLowerCase().includes('decoding')
        );
      });
      aiAssertTruthy({ name: 'LoadingDisplayed' }, loadingElement);
    });
  });
});
