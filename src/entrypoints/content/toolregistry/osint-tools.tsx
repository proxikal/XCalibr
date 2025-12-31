import React from 'react';
import {
  faMagnifyingGlass,
  faServer,
  faNetworkWired,
  faUser,
  faImage,
  faEnvelope,
  faLock,
  faSearch,
  faDiagramProject,
  faClockRotateLeft
} from '@fortawesome/free-solid-svg-icons';
import {
  WhoisLookupTool,
  DnsRecordViewerTool,
  ReverseIpLookupTool,
  UsernameSearchTool,
  ExifMetadataViewerTool,
  parseExif,
  EmailBreachCheckerTool,
  SslCertDecoderTool,
  GoogleDorkGeneratorTool,
  SubdomainFinderTool,
  WaybackMachineViewerTool
} from '../Tools';
import type {
  WhoisLookupData,
  DnsRecordViewerData,
  ReverseIpLookupData,
  UsernameSearchData,
  ExifMetadataViewerData,
  EmailBreachCheckerData,
  SslCertDecoderData,
  GoogleDorkGeneratorData,
  SubdomainFinderData,
  WaybackMachineViewerData
} from '../Tools/tool-types';
import type { ToolRegistryEntry } from './types';

export const buildOsintTools = (): ToolRegistryEntry[] => [
  {
    id: 'whoisLookup',
    title: 'Whois Lookup',
    subtitle: 'Domain RDAP data',
    category: 'OSINT',
    icon: faMagnifyingGlass,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    width: 400,
    render: (data, onChange) => (
      <WhoisLookupTool.Component
        data={data as WhoisLookupData | undefined}
        onChange={onChange}
        onLookup={async (domain) => {
          const result = await chrome.runtime.sendMessage({
            type: 'xcalibr-whois-lookup',
            payload: { domain }
          });
          onChange({ ...(data as WhoisLookupData), domain, ...result, loading: false });
        }}
      />
    )
  },
  {
    id: 'dnsRecordViewer',
    title: 'DNS Record Viewer',
    subtitle: 'A, MX, NS, TXT records',
    category: 'OSINT',
    icon: faServer,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    width: 420,
    render: (data, onChange) => (
      <DnsRecordViewerTool.Component
        data={data as DnsRecordViewerData | undefined}
        onChange={onChange}
        onLookup={async (domain) => {
          const result = await chrome.runtime.sendMessage({
            type: 'xcalibr-dns-lookup',
            payload: { domain }
          });
          onChange({ ...(data as DnsRecordViewerData), domain, ...result, loading: false });
        }}
      />
    )
  },
  {
    id: 'reverseIpLookup',
    title: 'Reverse IP Lookup',
    subtitle: 'Domains on IP',
    category: 'OSINT',
    icon: faNetworkWired,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    width: 400,
    render: (data, onChange) => (
      <ReverseIpLookupTool.Component
        data={data as ReverseIpLookupData | undefined}
        onChange={onChange}
        onLookup={async (ip) => {
          const result = await chrome.runtime.sendMessage({
            type: 'xcalibr-reverse-ip-lookup',
            payload: { ip }
          });
          onChange({ ...(data as ReverseIpLookupData), ip, ...result, loading: false });
        }}
      />
    )
  },
  {
    id: 'usernameSearch',
    title: 'Username Search',
    subtitle: 'Find username',
    category: 'OSINT',
    icon: faUser,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    width: 420,
    height: 450,
    render: (data, onChange) => (
      <UsernameSearchTool.Component
        data={data as UsernameSearchData | undefined}
        onChange={onChange}
        onSearch={async (username) => {
          onChange({ ...(data as UsernameSearchData), username, loading: true, error: undefined });
          const result = await chrome.runtime.sendMessage({
            type: 'xcalibr-username-search',
            payload: { username }
          });
          onChange({ ...(data as UsernameSearchData), username, ...result, loading: false });
        }}
      />
    )
  },
  {
    id: 'exifMetadataViewer',
    title: 'EXIF Metadata Viewer',
    subtitle: 'Image metadata',
    category: 'OSINT',
    icon: faImage,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    width: 380,
    height: 450,
    render: (data, onChange) => (
      <ExifMetadataViewerTool.Component
        data={data as ExifMetadataViewerData | undefined}
        onChange={onChange}
        onLoadFile={async (file) => {
          onChange({ loading: true, error: undefined, metadata: undefined });
          try {
            const buffer = await file.arrayBuffer();
            const metadata = parseExif(buffer);
            if (metadata) {
              onChange({ fileName: file.name, metadata, loading: false });
            } else {
              onChange({ fileName: file.name, error: 'No EXIF metadata found in image', loading: false });
            }
          } catch (err) {
            onChange({
              fileName: file.name,
              error: err instanceof Error ? err.message : 'Failed to read image',
              loading: false
            });
          }
        }}
      />
    )
  },
  {
    id: 'emailBreachChecker',
    title: 'Email Breach Checker',
    subtitle: 'Check pwned status',
    category: 'OSINT',
    icon: faEnvelope,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    width: 400,
    height: 450,
    render: (data, onChange) => (
      <EmailBreachCheckerTool.Component
        data={data as EmailBreachCheckerData | undefined}
        onChange={onChange}
        onCheck={async (email) => {
          onChange({ ...(data as EmailBreachCheckerData), email, loading: true, error: undefined });
          const result = await chrome.runtime.sendMessage({
            type: 'xcalibr-email-breach-check',
            payload: { email }
          });
          if (result.error) {
            onChange({
              ...(data as EmailBreachCheckerData),
              email,
              loading: false,
              error: result.error,
              checkedAt: Date.now()
            });
          } else {
            onChange({
              ...(data as EmailBreachCheckerData),
              email,
              breaches: result.breaches,
              loading: false,
              error: undefined,
              checkedAt: Date.now()
            });
          }
        }}
      />
    )
  },
  {
    id: 'sslCertDecoder',
    title: 'SSL Certificate Decoder',
    subtitle: 'View cert details',
    category: 'OSINT',
    icon: faLock,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    width: 400,
    height: 500,
    render: (data, onChange) => (
      <SslCertDecoderTool.Component
        data={data as SslCertDecoderData | undefined}
        onChange={onChange}
        onDecode={async (domain) => {
          onChange({ ...(data as SslCertDecoderData), domain, loading: true, error: undefined });
          const result = await chrome.runtime.sendMessage({
            type: 'xcalibr-ssl-cert-decode',
            payload: { domain }
          });
          if (result.error) {
            onChange({
              ...(data as SslCertDecoderData),
              domain,
              loading: false,
              error: result.error,
              fetchedAt: Date.now()
            });
          } else {
            onChange({
              ...(data as SslCertDecoderData),
              domain,
              certificate: result.certificate,
              loading: false,
              error: undefined,
              fetchedAt: Date.now()
            });
          }
        }}
      />
    )
  },
  {
    id: 'googleDorkGenerator',
    title: 'Google Dork Generator',
    subtitle: 'Advanced search queries',
    category: 'OSINT',
    icon: faSearch,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    width: 400,
    height: 500,
    render: (data, onChange) => (
      <GoogleDorkGeneratorTool.Component
        data={data as GoogleDorkGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'subdomainFinder',
    title: 'Subdomain Finder',
    subtitle: 'Find subdomains',
    category: 'OSINT',
    icon: faDiagramProject,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    width: 400,
    height: 450,
    render: (data, onChange) => (
      <SubdomainFinderTool.Component
        data={data as SubdomainFinderData | undefined}
        onChange={onChange}
        onFind={async (domain) => {
          onChange({ ...(data as SubdomainFinderData), domain, loading: true, error: undefined });
          const result = await chrome.runtime.sendMessage({
            type: 'xcalibr-subdomain-find',
            payload: { domain }
          });
          if (result.error) {
            onChange({
              ...(data as SubdomainFinderData),
              domain,
              loading: false,
              error: result.error,
              searchedAt: Date.now()
            });
          } else {
            onChange({
              ...(data as SubdomainFinderData),
              domain,
              subdomains: result.subdomains,
              loading: false,
              error: undefined,
              searchedAt: Date.now()
            });
          }
        }}
      />
    )
  },
  {
    id: 'waybackMachineViewer',
    title: 'Wayback Machine Viewer',
    subtitle: 'View archived pages',
    category: 'OSINT',
    icon: faClockRotateLeft,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    width: 600,
    height: 500,
    render: (data, onChange) => (
      <WaybackMachineViewerTool
        data={(data as WaybackMachineViewerData) || {}}
        onChange={onChange}
        onSearch={async (url) => {
          onChange({ ...(data as WaybackMachineViewerData), url, loading: true, error: undefined });
          const result = await chrome.runtime.sendMessage({
            type: 'xcalibr-wayback-search',
            payload: { url }
          });
          if (result.error) {
            onChange({
              ...(data as WaybackMachineViewerData),
              url,
              loading: false,
              error: result.error,
              searchedAt: Date.now()
            });
          } else {
            onChange({
              ...(data as WaybackMachineViewerData),
              url,
              snapshots: result.snapshots,
              loading: false,
              error: undefined,
              searchedAt: Date.now()
            });
          }
        }}
      />
    )
  }
];
