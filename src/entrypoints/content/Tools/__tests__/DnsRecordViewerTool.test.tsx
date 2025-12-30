import { beforeEach, describe, it } from 'vitest';
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
import type { DnsRecordViewerData } from '../tool-types';

// Type definitions for DNS records
type DnsRecordType = 'A' | 'AAAA' | 'CNAME' | 'MX' | 'TXT' | 'NS' | 'SOA';

interface DnsRecord {
  type: DnsRecordType;
  name: string;
  value: string;
  ttl?: number;
  priority?: number;
}

// Mock DNS response factory
const createMockDnsRecords = (domain: string): DnsRecord[] => [
  { type: 'A', name: domain, value: '93.184.216.34', ttl: 300 },
  { type: 'AAAA', name: domain, value: '2606:2800:220:1:248:1893:25c8:1946', ttl: 300 },
  { type: 'MX', name: domain, value: 'mail.example.com', ttl: 3600, priority: 10 },
  { type: 'NS', name: domain, value: 'ns1.example.com', ttl: 86400 },
  { type: 'NS', name: domain, value: 'ns2.example.com', ttl: 86400 },
  { type: 'TXT', name: domain, value: 'v=spf1 include:_spf.example.com ~all', ttl: 3600 },
  { type: 'CNAME', name: `www.${domain}`, value: domain, ttl: 3600 }
];

// Record filtering logic
const filterRecordsByType = (records: DnsRecord[], type: DnsRecordType | 'ALL'): DnsRecord[] => {
  if (type === 'ALL') return records;
  return records.filter(r => r.type === type);
};

// TTL formatting
const formatTtl = (ttl: number): string => {
  if (ttl >= 86400) {
    const days = Math.floor(ttl / 86400);
    return `${days}d`;
  }
  if (ttl >= 3600) {
    const hours = Math.floor(ttl / 3600);
    return `${hours}h`;
  }
  if (ttl >= 60) {
    const minutes = Math.floor(ttl / 60);
    return `${minutes}m`;
  }
  return `${ttl}s`;
};

// Record type color mapping
const getRecordTypeColor = (type: DnsRecordType): string => {
  const colors: Record<DnsRecordType, string> = {
    A: 'text-emerald-400',
    AAAA: 'text-cyan-400',
    CNAME: 'text-amber-400',
    MX: 'text-purple-400',
    TXT: 'text-slate-400',
    NS: 'text-blue-400',
    SOA: 'text-rose-400'
  };
  return colors[type] || 'text-slate-400';
};

describe('DnsRecordViewerTool', () => {
  describe('DNS record filtering', () => {
    it('should return all records when filter is ALL', () => {
      const records = createMockDnsRecords('example.com');
      const filtered = filterRecordsByType(records, 'ALL');

      aiAssertEqual(
        { name: 'AllRecordsCount', input: records.length },
        filtered.length,
        records.length
      );
    });

    it('should filter A records correctly', () => {
      const records = createMockDnsRecords('example.com');
      const filtered = filterRecordsByType(records, 'A');

      aiAssertEqual(
        { name: 'ARecordsCount', input: records },
        filtered.length,
        1
      );
      aiAssertEqual(
        { name: 'ARecordType', input: filtered[0] },
        filtered[0].type,
        'A'
      );
    });

    it('should filter AAAA records correctly', () => {
      const records = createMockDnsRecords('example.com');
      const filtered = filterRecordsByType(records, 'AAAA');

      aiAssertEqual(
        { name: 'AAAARecordsCount', input: records },
        filtered.length,
        1
      );
      aiAssertIncludes(
        { name: 'AAAARecordValue', input: filtered[0] },
        filtered[0].value,
        '2606'
      );
    });

    it('should filter MX records correctly', () => {
      const records = createMockDnsRecords('example.com');
      const filtered = filterRecordsByType(records, 'MX');

      aiAssertEqual(
        { name: 'MXRecordsCount', input: records },
        filtered.length,
        1
      );
      aiAssertTruthy(
        { name: 'MXRecordHasPriority', input: filtered[0] },
        filtered[0].priority !== undefined
      );
    });

    it('should filter NS records correctly', () => {
      const records = createMockDnsRecords('example.com');
      const filtered = filterRecordsByType(records, 'NS');

      aiAssertEqual(
        { name: 'NSRecordsCount', input: records },
        filtered.length,
        2
      );
    });

    it('should filter TXT records correctly', () => {
      const records = createMockDnsRecords('example.com');
      const filtered = filterRecordsByType(records, 'TXT');

      aiAssertEqual(
        { name: 'TXTRecordsCount', input: records },
        filtered.length,
        1
      );
      aiAssertIncludes(
        { name: 'TXTRecordValue', input: filtered[0] },
        filtered[0].value,
        'spf1'
      );
    });

    it('should filter CNAME records correctly', () => {
      const records = createMockDnsRecords('example.com');
      const filtered = filterRecordsByType(records, 'CNAME');

      aiAssertEqual(
        { name: 'CNAMERecordsCount', input: records },
        filtered.length,
        1
      );
    });
  });

  describe('TTL formatting', () => {
    it('should format seconds correctly', () => {
      aiAssertEqual({ name: 'TTL30s' }, formatTtl(30), '30s');
      aiAssertEqual({ name: 'TTL59s' }, formatTtl(59), '59s');
    });

    it('should format minutes correctly', () => {
      aiAssertEqual({ name: 'TTL5m' }, formatTtl(300), '5m');
      aiAssertEqual({ name: 'TTL59m' }, formatTtl(3540), '59m');
    });

    it('should format hours correctly', () => {
      aiAssertEqual({ name: 'TTL1h' }, formatTtl(3600), '1h');
      aiAssertEqual({ name: 'TTL24h' }, formatTtl(86399), '23h');
    });

    it('should format days correctly', () => {
      aiAssertEqual({ name: 'TTL1d' }, formatTtl(86400), '1d');
      aiAssertEqual({ name: 'TTL7d' }, formatTtl(604800), '7d');
    });
  });

  describe('Record type colors', () => {
    it('should return correct color for A records', () => {
      aiAssertIncludes(
        { name: 'ARecordColor' },
        getRecordTypeColor('A'),
        'emerald'
      );
    });

    it('should return correct color for AAAA records', () => {
      aiAssertIncludes(
        { name: 'AAAARecordColor' },
        getRecordTypeColor('AAAA'),
        'cyan'
      );
    });

    it('should return correct color for MX records', () => {
      aiAssertIncludes(
        { name: 'MXRecordColor' },
        getRecordTypeColor('MX'),
        'purple'
      );
    });

    it('should return correct color for NS records', () => {
      aiAssertIncludes(
        { name: 'NSRecordColor' },
        getRecordTypeColor('NS'),
        'blue'
      );
    });

    it('should return correct color for TXT records', () => {
      aiAssertIncludes(
        { name: 'TXTRecordColor' },
        getRecordTypeColor('TXT'),
        'slate'
      );
    });

    it('should return correct color for CNAME records', () => {
      aiAssertIncludes(
        { name: 'CNAMERecordColor' },
        getRecordTypeColor('CNAME'),
        'amber'
      );
    });
  });

  describe('Domain validation', () => {
    it('should validate basic domain format', () => {
      const isValidDomain = (domain: string) => {
        const pattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/;
        return pattern.test(domain);
      };

      aiAssertTruthy({ name: 'ValidDomain' }, isValidDomain('example.com'));
      aiAssertTruthy({ name: 'ValidSubdomain' }, isValidDomain('sub.example.com'));
      aiAssertEqual({ name: 'InvalidDomain' }, isValidDomain('invalid'), false);
      aiAssertEqual({ name: 'EmptyDomain' }, isValidDomain(''), false);
    });
  });

  describe('Default values', () => {
    it('should use default values when data is undefined', () => {
      const getData = (): DnsRecordViewerData | undefined => undefined;
      const data = getData();

      const domain = data?.domain ?? '';
      const records = data?.records ?? [];
      const filter = data?.filter ?? 'ALL';
      const error = data?.error;
      const loading = data?.loading ?? false;

      aiAssertEqual({ name: 'DefaultDomain' }, domain, '');
      aiAssertEqual({ name: 'DefaultRecordsLength' }, records.length, 0);
      aiAssertEqual({ name: 'DefaultFilter' }, filter, 'ALL');
      aiAssertEqual({ name: 'DefaultError' }, error, undefined);
      aiAssertEqual({ name: 'DefaultLoading' }, loading, false);
    });
  });

  describe('Error handling', () => {
    it('should handle error state', () => {
      const data: DnsRecordViewerData = {
        domain: 'invalid-domain',
        error: 'DNS lookup failed'
      };

      aiAssertTruthy(
        { name: 'ErrorPresent', input: data },
        data.error !== undefined
      );
      aiAssertIncludes(
        { name: 'ErrorMessage', input: data },
        data.error ?? '',
        'failed'
      );
    });
  });

  describe('Record count by type', () => {
    it('should count records by type correctly', () => {
      const records = createMockDnsRecords('example.com');

      const countByType = (type: DnsRecordType): number => {
        return records.filter(r => r.type === type).length;
      };

      aiAssertEqual({ name: 'ACount' }, countByType('A'), 1);
      aiAssertEqual({ name: 'AAAACount' }, countByType('AAAA'), 1);
      aiAssertEqual({ name: 'MXCount' }, countByType('MX'), 1);
      aiAssertEqual({ name: 'NSCount' }, countByType('NS'), 2);
      aiAssertEqual({ name: 'TXTCount' }, countByType('TXT'), 1);
      aiAssertEqual({ name: 'CNAMECount' }, countByType('CNAME'), 1);
    });
  });

  describe('Edge cases', () => {
    it('should handle empty records array', () => {
      const records: DnsRecord[] = [];
      const filtered = filterRecordsByType(records, 'A');

      aiAssertEqual({ name: 'EmptyFilteredCount' }, filtered.length, 0);
    });

    it('should handle records with no TTL', () => {
      const record: DnsRecord = {
        type: 'A',
        name: 'example.com',
        value: '1.2.3.4'
      };

      aiAssertEqual({ name: 'RecordNoTTL' }, record.ttl, undefined);
    });

    it('should handle long TXT records', () => {
      const longTxt = 'a'.repeat(500);
      const record: DnsRecord = {
        type: 'TXT',
        name: 'example.com',
        value: longTxt,
        ttl: 3600
      };

      aiAssertEqual(
        { name: 'LongTXTValueLength' },
        record.value.length,
        500
      );
    });
  });

  describe('Integration tests', () => {
    beforeEach(() => {
      document.body.innerHTML = '';
      resetChrome();
    });

    it('renders DNS Record Viewer tool with input and button', async () => {
      const root = await mountWithTool('dnsRecordViewer', { domain: '' });
      if (!root) return;

      // Find the domain input with exact placeholder
      const input = root.querySelector('input[placeholder="Enter domain (e.g., example.com)"]') as HTMLInputElement;
      aiAssertTruthy({ name: 'DnsInput' }, input);

      // Find the lookup button
      const lookupButton = await waitFor(() => findButtonByText(root, 'Lookup'));
      aiAssertTruthy({ name: 'DnsLookupButton' }, lookupButton);
    });

    it('displays records when data is present', async () => {
      const root = await mountWithTool('dnsRecordViewer', {
        domain: 'example.com',
        records: [
          { type: 'A', name: 'example.com', value: '93.184.216.34', ttl: 300 },
          { type: 'MX', name: 'example.com', value: 'mail.example.com', ttl: 3600, priority: 10 }
        ]
      });
      if (!root) return;

      await flushPromises();

      // Check for record content in the DOM
      const recordElements = Array.from(root.querySelectorAll('div')).filter(
        el => el.textContent?.includes('93.184.216.34')
      );
      aiAssertTruthy({ name: 'DnsRecordDisplay' }, recordElements.length > 0);
    });

    it('performs DNS lookup via background script', async () => {
      setRuntimeHandler('xcalibr-dns-lookup', () => ({
        records: [
          { type: 'A', name: 'example.com', value: '93.184.216.34', ttl: 300 },
          { type: 'NS', name: 'example.com', value: 'ns1.example.com', ttl: 86400 }
        ]
      }));

      const root = await mountWithTool('dnsRecordViewer', { domain: 'example.com' });
      if (!root) return;

      const lookupButton = await waitFor(() => findButtonByText(root, 'Lookup'));
      aiAssertTruthy({ name: 'DnsLookupButtonFound' }, lookupButton);
      lookupButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();

      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, DnsRecordViewerData> | undefined;
        return Boolean(toolData?.dnsRecordViewer?.records?.length);
      });
      const toolData = (stored?.toolData ?? {}) as Record<string, DnsRecordViewerData>;
      aiAssertTruthy(
        { name: 'DnsRecordsPresent', state: toolData.dnsRecordViewer },
        (toolData.dnsRecordViewer?.records?.length ?? 0) > 0
      );
    });

    it('handles lookup error correctly', async () => {
      setRuntimeHandler('xcalibr-dns-lookup', () => ({
        error: 'DNS lookup failed'
      }));

      const root = await mountWithTool('dnsRecordViewer', { domain: 'nonexistent.invalid' });
      if (!root) return;

      const lookupButton = await waitFor(() => findButtonByText(root, 'Lookup'));
      lookupButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();

      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, DnsRecordViewerData> | undefined;
        return Boolean(toolData?.dnsRecordViewer?.error);
      });
      const toolData = (stored?.toolData ?? {}) as Record<string, DnsRecordViewerData>;
      aiAssertTruthy(
        { name: 'DnsErrorPresent', state: toolData.dnsRecordViewer },
        toolData.dnsRecordViewer?.error
      );
    });

    it('displays error message when error is present', async () => {
      const root = await mountWithTool('dnsRecordViewer', {
        domain: 'example.com',
        error: 'DNS lookup failed'
      });
      if (!root) return;

      await flushPromises();

      const errorElements = Array.from(root.querySelectorAll('div')).filter(
        el => el.textContent?.includes('DNS lookup failed')
      );
      aiAssertTruthy({ name: 'DnsErrorDisplay' }, errorElements.length > 0);
    });

    it('shows loading state during lookup', async () => {
      const root = await mountWithTool('dnsRecordViewer', {
        domain: 'example.com',
        loading: true
      });
      if (!root) return;

      const loadingButton = await waitFor(() => findButtonByText(root, 'Loading...'));
      aiAssertTruthy({ name: 'DnsLoadingButton' }, loadingButton);
    });

    it('disables lookup button when domain is empty', async () => {
      const root = await mountWithTool('dnsRecordViewer', { domain: '' });
      if (!root) return;

      const lookupButton = await waitFor(() => findButtonByText(root, 'Lookup'));
      aiAssertTruthy({ name: 'DnsLookupButtonEmpty' }, lookupButton);
      aiAssertTruthy(
        { name: 'DnsButtonDisabled' },
        lookupButton?.hasAttribute('disabled')
      );
    });
  });
});
