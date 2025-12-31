import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faSearch, faCopy, faCloud, faExternalLinkAlt, faExclamationTriangle, faDownload, faFilter } from '@fortawesome/free-solid-svg-icons';

export type CloudProvider = 'aws' | 'gcp' | 'azure' | 'digitalocean' | 'alibaba';

export type CloudBucket = {
  url: string;
  bucketName: string;
  region?: string;
  provider: CloudProvider;
  source: string;
};

export type S3BucketFinderData = {
  buckets?: CloudBucket[];
  scannedAt?: number;
  error?: string;
  filterProvider?: CloudProvider | 'all';
};

type Props = {
  data: S3BucketFinderData | undefined;
  onChange: (data: S3BucketFinderData) => void;
};

// Cloud storage patterns for multiple providers
const CLOUD_PATTERNS: { provider: CloudProvider; patterns: RegExp[]; extractor: (url: string) => { name: string; region?: string } }[] = [
  // AWS S3
  {
    provider: 'aws',
    patterns: [
      /https?:\/\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3\.amazonaws\.com/gi,
      /https?:\/\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3[.-]([a-z0-9-]+)\.amazonaws\.com/gi,
      /https?:\/\/s3\.amazonaws\.com\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])/gi,
      /https?:\/\/s3[.-]([a-z0-9-]+)\.amazonaws\.com\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])/gi,
      /https?:\/\/[a-z0-9.-]+\.s3[a-z0-9.-]*\.amazonaws\.com[^\s"'<>]*/gi,
    ],
    extractor: (url: string) => {
      let match = url.match(/https?:\/\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3[.-]([a-z0-9-]+)\.amazonaws\.com/i);
      if (match) return { name: match[1], region: match[2] };
      match = url.match(/https?:\/\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3\.amazonaws\.com/i);
      if (match) return { name: match[1], region: 'us-east-1' };
      match = url.match(/https?:\/\/s3[.-]?([a-z0-9-]*)\.?amazonaws\.com\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])/i);
      if (match) return { name: match[2], region: match[1] || 'us-east-1' };
      return { name: 'unknown' };
    }
  },
  // Google Cloud Storage
  {
    provider: 'gcp',
    patterns: [
      /https?:\/\/storage\.googleapis\.com\/([a-z0-9][a-z0-9._-]{1,61}[a-z0-9])/gi,
      /https?:\/\/([a-z0-9][a-z0-9._-]{1,61}[a-z0-9])\.storage\.googleapis\.com/gi,
      /https?:\/\/storage\.cloud\.google\.com\/([a-z0-9][a-z0-9._-]{1,61}[a-z0-9])/gi,
      /https?:\/\/([a-z0-9][a-z0-9._-]{1,61}[a-z0-9])\.storage\.cloud\.google\.com/gi,
      /gs:\/\/([a-z0-9][a-z0-9._-]{1,61}[a-z0-9])/gi,
    ],
    extractor: (url: string) => {
      let match = url.match(/https?:\/\/storage\.(?:googleapis|cloud\.google)\.com\/([a-z0-9][a-z0-9._-]{1,61}[a-z0-9])/i);
      if (match) return { name: match[1] };
      match = url.match(/https?:\/\/([a-z0-9][a-z0-9._-]{1,61}[a-z0-9])\.storage\.(?:googleapis|cloud\.google)\.com/i);
      if (match) return { name: match[1] };
      match = url.match(/gs:\/\/([a-z0-9][a-z0-9._-]{1,61}[a-z0-9])/i);
      if (match) return { name: match[1] };
      return { name: 'unknown' };
    }
  },
  // Azure Blob Storage
  {
    provider: 'azure',
    patterns: [
      /https?:\/\/([a-z0-9]{3,24})\.blob\.core\.windows\.net\/([a-z0-9][a-z0-9-]{1,61}[a-z0-9])/gi,
      /https?:\/\/([a-z0-9]{3,24})\.blob\.core\.windows\.net/gi,
      /https?:\/\/([a-z0-9]{3,24})\.dfs\.core\.windows\.net/gi,
      /https?:\/\/([a-z0-9]{3,24})\.file\.core\.windows\.net/gi,
    ],
    extractor: (url: string) => {
      const match = url.match(/https?:\/\/([a-z0-9]{3,24})\.(?:blob|dfs|file)\.core\.windows\.net(?:\/([a-z0-9][a-z0-9-]{1,61}[a-z0-9]))?/i);
      if (match) return { name: match[2] || match[1], region: 'azure' };
      return { name: 'unknown' };
    }
  },
  // DigitalOcean Spaces
  {
    provider: 'digitalocean',
    patterns: [
      /https?:\/\/([a-z0-9][a-z0-9-]{1,61}[a-z0-9])\.([a-z0-9-]+)\.digitaloceanspaces\.com/gi,
      /https?:\/\/([a-z0-9-]+)\.digitaloceanspaces\.com\/([a-z0-9][a-z0-9-]{1,61}[a-z0-9])/gi,
    ],
    extractor: (url: string) => {
      let match = url.match(/https?:\/\/([a-z0-9][a-z0-9-]{1,61}[a-z0-9])\.([a-z0-9-]+)\.digitaloceanspaces\.com/i);
      if (match) return { name: match[1], region: match[2] };
      match = url.match(/https?:\/\/([a-z0-9-]+)\.digitaloceanspaces\.com\/([a-z0-9][a-z0-9-]{1,61}[a-z0-9])/i);
      if (match) return { name: match[2], region: match[1] };
      return { name: 'unknown' };
    }
  },
  // Alibaba Cloud OSS
  {
    provider: 'alibaba',
    patterns: [
      /https?:\/\/([a-z0-9][a-z0-9-]{1,61}[a-z0-9])\.oss-([a-z0-9-]+)\.aliyuncs\.com/gi,
      /https?:\/\/oss-([a-z0-9-]+)\.aliyuncs\.com\/([a-z0-9][a-z0-9-]{1,61}[a-z0-9])/gi,
    ],
    extractor: (url: string) => {
      let match = url.match(/https?:\/\/([a-z0-9][a-z0-9-]{1,61}[a-z0-9])\.oss-([a-z0-9-]+)\.aliyuncs\.com/i);
      if (match) return { name: match[1], region: match[2] };
      match = url.match(/https?:\/\/oss-([a-z0-9-]+)\.aliyuncs\.com\/([a-z0-9][a-z0-9-]{1,61}[a-z0-9])/i);
      if (match) return { name: match[2], region: match[1] };
      return { name: 'unknown' };
    }
  }
];

const PROVIDER_COLORS: Record<CloudProvider, { bg: string; text: string; label: string }> = {
  aws: { bg: 'bg-orange-900/50', text: 'text-orange-300', label: 'AWS S3' },
  gcp: { bg: 'bg-blue-900/50', text: 'text-blue-300', label: 'GCP Storage' },
  azure: { bg: 'bg-cyan-900/50', text: 'text-cyan-300', label: 'Azure Blob' },
  digitalocean: { bg: 'bg-purple-900/50', text: 'text-purple-300', label: 'DO Spaces' },
  alibaba: { bg: 'bg-amber-900/50', text: 'text-amber-300', label: 'Alibaba OSS' }
};

const S3BucketFinder: React.FC<Props> = ({ data, onChange }) => {
  const buckets = data?.buckets ?? [];
  const scannedAt = data?.scannedAt;
  const error = data?.error;
  const filterProvider = data?.filterProvider ?? 'all';
  const [scanning, setScanning] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const scanPage = () => {
    setScanning(true);
    try {
      const foundBuckets: CloudBucket[] = [];
      const seenUrls = new Set<string>();
      const html = document.documentElement.outerHTML;

      // Helper to scan a URL against all cloud patterns
      const scanUrl = (url: string, source: string) => {
        if (seenUrls.has(url)) return;

        for (const cloudConfig of CLOUD_PATTERNS) {
          for (const pattern of cloudConfig.patterns) {
            pattern.lastIndex = 0;
            if (pattern.test(url)) {
              seenUrls.add(url);
              const { name, region } = cloudConfig.extractor(url);
              foundBuckets.push({
                url,
                bucketName: name,
                region,
                provider: cloudConfig.provider,
                source
              });
              return;
            }
          }
        }
      };

      // Scan full page source
      for (const cloudConfig of CLOUD_PATTERNS) {
        for (const pattern of cloudConfig.patterns) {
          pattern.lastIndex = 0;
          const matches = html.matchAll(pattern);
          for (const match of matches) {
            const url = match[0].split(/[\s"'<>]/)[0];
            scanUrl(url, 'page source');
          }
        }
      }

      // Scan script srcs
      document.querySelectorAll('script[src]').forEach(script => {
        const src = script.getAttribute('src') || '';
        scanUrl(src, 'script src');
      });

      // Scan link hrefs
      document.querySelectorAll('link[href]').forEach(link => {
        const href = link.getAttribute('href') || '';
        scanUrl(href, 'link href');
      });

      // Scan img srcs
      document.querySelectorAll('img[src], source[src], video[src], audio[src]').forEach(el => {
        const src = el.getAttribute('src') || '';
        scanUrl(src, 'media src');
      });

      // Scan CSS background images
      document.querySelectorAll('[style*="url"]').forEach(el => {
        const style = el.getAttribute('style') || '';
        const urlMatch = style.match(/url\(['"]?([^'")\s]+)['"]?\)/i);
        if (urlMatch) {
          scanUrl(urlMatch[1], 'css background');
        }
      });

      // Deduplicate by bucket name + provider
      const uniqueBuckets = foundBuckets.reduce((acc, bucket) => {
        if (!acc.some(b => b.bucketName === bucket.bucketName && b.provider === bucket.provider)) {
          acc.push(bucket);
        }
        return acc;
      }, [] as CloudBucket[]);

      onChange({
        ...data,
        buckets: uniqueBuckets,
        scannedAt: Date.now(),
        error: undefined
      });
    } catch (e) {
      onChange({
        ...data,
        error: e instanceof Error ? e.message : 'Scan failed',
        scannedAt: Date.now()
      });
    } finally {
      setScanning(false);
    }
  };

  const filteredBuckets = buckets.filter(b =>
    filterProvider === 'all' || b.provider === filterProvider
  );

  const providerCounts = buckets.reduce((acc, b) => {
    acc[b.provider] = (acc[b.provider] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const exportAsJson = () => {
    const exportData = {
      url: window.location.href,
      scannedAt: scannedAt ? new Date(scannedAt).toISOString() : null,
      buckets: filteredBuckets
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cloud-storage-${window.location.hostname}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyToClipboard = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 1500);
  };

  const copyAllBuckets = () => {
    const text = buckets.map(b => b.bucketName).join('\n');
    navigator.clipboard.writeText(text);
    setCopiedIndex(-1);
    setTimeout(() => setCopiedIndex(null), 1500);
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">Cloud Storage Finder</div>
        <div className="flex gap-1">
          {buckets.length > 0 && (
            <>
              <button
                onClick={exportAsJson}
                className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
                title="Export as JSON"
              >
                <FontAwesomeIcon icon={faDownload} className="w-2.5 h-2.5" />
              </button>
              <button
                onClick={copyAllBuckets}
                className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
                title="Copy all bucket names"
              >
                <FontAwesomeIcon icon={faCopy} className="w-2.5 h-2.5" />
                {copiedIndex === -1 && <span className="text-green-400 ml-1">!</span>}
              </button>
            </>
          )}
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Finds cloud storage URLs: AWS S3, GCP Storage, Azure Blob, DigitalOcean Spaces, Alibaba OSS.
      </div>

      <button
        onClick={scanPage}
        disabled={scanning}
        className="w-full rounded bg-orange-600/20 border border-orange-500/30 px-2 py-1.5 text-[11px] text-orange-300 hover:bg-orange-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2 mb-3"
      >
        <FontAwesomeIcon icon={faSearch} className="w-3 h-3" />
        {scanning ? 'Scanning...' : 'Find Cloud Storage'}
      </button>

      {/* Provider Filter */}
      {scannedAt && buckets.length > 0 && (
        <div className="flex items-center gap-2 mb-3 flex-wrap">
          <FontAwesomeIcon icon={faFilter} className="w-2.5 h-2.5 text-slate-500" />
          {(['all', 'aws', 'gcp', 'azure', 'digitalocean', 'alibaba'] as const).map(provider => {
            const count = provider === 'all' ? buckets.length : (providerCounts[provider] || 0);
            if (provider !== 'all' && count === 0) return null;
            return (
              <button
                key={provider}
                onClick={() => onChange({ ...data, filterProvider: provider })}
                className={`px-2 py-0.5 rounded text-[9px] transition-colors ${
                  filterProvider === provider
                    ? 'bg-orange-600/30 text-orange-300 border border-orange-500/50'
                    : 'bg-slate-800 text-slate-400 border border-slate-700 hover:border-slate-500'
                }`}
              >
                {provider === 'all' ? 'All' : PROVIDER_COLORS[provider].label}
                {count > 0 && <span className="ml-1 opacity-60">({count})</span>}
              </button>
            );
          })}
        </div>
      )}

      {error && (
        <div className="text-red-400 text-[11px] bg-red-900/20 border border-red-500/30 p-2 rounded mb-3">
          {error}
        </div>
      )}

      {scannedAt && (
        <div className="text-[10px] text-slate-500 mb-3">
          Last scanned: {new Date(scannedAt).toLocaleTimeString()}
        </div>
      )}

      {filteredBuckets.length > 0 && (
        <div className="flex-1 overflow-y-auto min-h-0">
          <div className="flex items-center gap-2 text-orange-400 text-[11px] font-medium mb-2">
            <FontAwesomeIcon icon={faCloud} className="w-3 h-3" />
            Cloud Storage Found ({filteredBuckets.length}{filteredBuckets.length !== buckets.length ? `/${buckets.length}` : ''})
          </div>

          <div className="rounded border border-yellow-500/30 bg-yellow-900/20 p-2 mb-3 text-[10px] text-yellow-400">
            <FontAwesomeIcon icon={faExclamationTriangle} className="w-2.5 h-2.5 mr-1" />
            Found buckets may contain sensitive data. Check for misconfigurations.
          </div>

          <div className="space-y-2">
            {filteredBuckets.map((bucket, idx) => {
              const providerStyle = PROVIDER_COLORS[bucket.provider];
              return (
                <div key={idx} className="rounded border border-slate-700 bg-slate-800/50 p-2">
                  <div className="flex justify-between items-start">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-orange-400 text-[11px] font-medium flex items-center gap-1">
                          <FontAwesomeIcon icon={faCloud} className="w-2.5 h-2.5" />
                          {bucket.bucketName}
                        </span>
                        <span className={`text-[8px] px-1.5 py-0.5 rounded ${providerStyle.bg} ${providerStyle.text}`}>
                          {providerStyle.label}
                        </span>
                      </div>
                      {bucket.region && bucket.region !== 'azure' && (
                        <div className="text-slate-500 text-[10px] mt-0.5">
                          Region: {bucket.region}
                        </div>
                      )}
                      <div className="text-slate-400 text-[10px] font-mono mt-1 break-all">
                        {bucket.url}
                      </div>
                      <div className="text-slate-600 text-[9px] mt-1">
                        {bucket.source}
                      </div>
                    </div>
                    <div className="flex gap-1 ml-2 flex-shrink-0">
                      <a
                        href={bucket.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-[9px] text-slate-500 hover:text-blue-400 p-1"
                        title="Open URL"
                      >
                        <FontAwesomeIcon icon={faExternalLinkAlt} className="w-2.5 h-2.5" />
                      </a>
                      <button
                        onClick={() => copyToClipboard(bucket.url, idx)}
                        className="text-[9px] text-slate-500 hover:text-slate-300 p-1"
                        title="Copy URL"
                      >
                        <FontAwesomeIcon icon={faCopy} className="w-2.5 h-2.5" />
                      </button>
                    </div>
                  </div>
                  {copiedIndex === idx && (
                    <span className="text-green-400 text-[9px]">Copied!</span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {scannedAt && filteredBuckets.length === 0 && (
        <div className="text-[11px] text-green-400 text-center py-4">
          No cloud storage URLs found on this page.
        </div>
      )}

      <div className="text-[10px] text-slate-500 border-t border-slate-700 pt-2 mt-3">
        <div><strong>Supported:</strong> AWS S3, GCP Storage, Azure Blob, DigitalOcean Spaces, Alibaba OSS</div>
      </div>
    </div>
  );
};

export class S3BucketFinderTool {
  static Component = S3BucketFinder;
}
