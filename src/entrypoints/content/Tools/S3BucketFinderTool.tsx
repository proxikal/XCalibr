import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faSearch, faCopy, faCloud, faExternalLinkAlt, faExclamationTriangle } from '@fortawesome/free-solid-svg-icons';

export type S3Bucket = {
  url: string;
  bucketName: string;
  region?: string;
  source: string;
};

export type S3BucketFinderData = {
  buckets?: S3Bucket[];
  scannedAt?: number;
  error?: string;
};

type Props = {
  data: S3BucketFinderData | undefined;
  onChange: (data: S3BucketFinderData) => void;
};

// Patterns to detect S3 bucket URLs
const S3_PATTERNS = [
  // Virtual-hosted style
  /https?:\/\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3\.amazonaws\.com/gi,
  /https?:\/\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3-([a-z0-9-]+)\.amazonaws\.com/gi,
  /https?:\/\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3\.([a-z0-9-]+)\.amazonaws\.com/gi,
  // Path style
  /https?:\/\/s3\.amazonaws\.com\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])/gi,
  /https?:\/\/s3-([a-z0-9-]+)\.amazonaws\.com\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])/gi,
  /https?:\/\/s3\.([a-z0-9-]+)\.amazonaws\.com\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])/gi,
  // Generic S3 pattern
  /https?:\/\/[a-z0-9.-]+\.s3[a-z0-9.-]*\.amazonaws\.com[^\s"'<>]*/gi,
  /https?:\/\/s3[a-z0-9.-]*\.amazonaws\.com\/[a-z0-9][^\s"'<>]*/gi
];

const extractBucketName = (url: string): { name: string; region?: string } => {
  // Virtual-hosted style with region
  let match = url.match(/https?:\/\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3[.-]([a-z0-9-]+)\.amazonaws\.com/i);
  if (match) {
    return { name: match[1], region: match[2] };
  }

  // Virtual-hosted style without region
  match = url.match(/https?:\/\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3\.amazonaws\.com/i);
  if (match) {
    return { name: match[1], region: 'us-east-1' };
  }

  // Path style
  match = url.match(/https?:\/\/s3[.-]?([a-z0-9-]*)\.?amazonaws\.com\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])/i);
  if (match) {
    return { name: match[2], region: match[1] || 'us-east-1' };
  }

  return { name: 'unknown' };
};

const S3BucketFinder: React.FC<Props> = ({ data, onChange }) => {
  const buckets = data?.buckets ?? [];
  const scannedAt = data?.scannedAt;
  const error = data?.error;
  const [scanning, setScanning] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const scanPage = () => {
    setScanning(true);
    try {
      const foundBuckets: S3Bucket[] = [];
      const seenUrls = new Set<string>();
      const html = document.documentElement.outerHTML;

      // Scan with all patterns
      S3_PATTERNS.forEach(pattern => {
        const matches = html.matchAll(pattern);
        for (const match of matches) {
          const url = match[0].split(/[\s"'<>]/)[0]; // Clean URL
          if (!seenUrls.has(url)) {
            seenUrls.add(url);
            const { name, region } = extractBucketName(url);
            foundBuckets.push({
              url,
              bucketName: name,
              region,
              source: 'page source'
            });
          }
        }
      });

      // Scan script srcs
      document.querySelectorAll('script[src]').forEach(script => {
        const src = script.getAttribute('src') || '';
        S3_PATTERNS.forEach(pattern => {
          if (pattern.test(src) && !seenUrls.has(src)) {
            seenUrls.add(src);
            const { name, region } = extractBucketName(src);
            foundBuckets.push({
              url: src,
              bucketName: name,
              region,
              source: 'script src'
            });
          }
          pattern.lastIndex = 0; // Reset regex
        });
      });

      // Scan link hrefs
      document.querySelectorAll('link[href]').forEach(link => {
        const href = link.getAttribute('href') || '';
        S3_PATTERNS.forEach(pattern => {
          if (pattern.test(href) && !seenUrls.has(href)) {
            seenUrls.add(href);
            const { name, region } = extractBucketName(href);
            foundBuckets.push({
              url: href,
              bucketName: name,
              region,
              source: 'link href'
            });
          }
          pattern.lastIndex = 0;
        });
      });

      // Scan img srcs
      document.querySelectorAll('img[src]').forEach(img => {
        const src = img.getAttribute('src') || '';
        S3_PATTERNS.forEach(pattern => {
          if (pattern.test(src) && !seenUrls.has(src)) {
            seenUrls.add(src);
            const { name, region } = extractBucketName(src);
            foundBuckets.push({
              url: src,
              bucketName: name,
              region,
              source: 'image src'
            });
          }
          pattern.lastIndex = 0;
        });
      });

      // Deduplicate by bucket name
      const uniqueBuckets = foundBuckets.reduce((acc, bucket) => {
        if (!acc.some(b => b.bucketName === bucket.bucketName)) {
          acc.push(bucket);
        }
        return acc;
      }, [] as S3Bucket[]);

      onChange({
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
        <div className="text-xs text-slate-200">S3 Bucket Finder</div>
        <div className="flex gap-2">
          {buckets.length > 0 && (
            <button
              onClick={copyAllBuckets}
              className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors flex items-center gap-1"
            >
              <FontAwesomeIcon icon={faCopy} className="w-2.5 h-2.5" />
              Copy All
              {copiedIndex === -1 && <span className="text-green-400 ml-1">Copied!</span>}
            </button>
          )}
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Extracts Amazon S3 bucket URLs from page source, scripts, and assets.
      </div>

      <button
        onClick={scanPage}
        disabled={scanning}
        className="w-full rounded bg-orange-600/20 border border-orange-500/30 px-2 py-1.5 text-[11px] text-orange-300 hover:bg-orange-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2 mb-3"
      >
        <FontAwesomeIcon icon={faSearch} className="w-3 h-3" />
        {scanning ? 'Scanning...' : 'Find S3 Buckets'}
      </button>

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

      {buckets.length > 0 && (
        <div className="flex-1 overflow-y-auto min-h-0">
          <div className="flex items-center gap-2 text-orange-400 text-[11px] font-medium mb-2">
            <FontAwesomeIcon icon={faCloud} className="w-3 h-3" />
            S3 Buckets Found ({buckets.length})
          </div>

          <div className="rounded border border-yellow-500/30 bg-yellow-900/20 p-2 mb-3 text-[10px] text-yellow-400">
            <FontAwesomeIcon icon={faExclamationTriangle} className="w-2.5 h-2.5 mr-1" />
            Found buckets may contain sensitive data. Check for misconfigurations.
          </div>

          <div className="space-y-2">
            {buckets.map((bucket, idx) => (
              <div key={idx} className="rounded border border-slate-700 bg-slate-800/50 p-2">
                <div className="flex justify-between items-start">
                  <div className="flex-1">
                    <div className="text-orange-400 text-[11px] font-medium flex items-center gap-2">
                      <FontAwesomeIcon icon={faCloud} className="w-2.5 h-2.5" />
                      {bucket.bucketName}
                    </div>
                    {bucket.region && (
                      <div className="text-slate-500 text-[10px] mt-0.5">
                        Region: {bucket.region}
                      </div>
                    )}
                    <div className="text-slate-400 text-[10px] font-mono mt-1 break-all">
                      {bucket.url}
                    </div>
                    <div className="text-slate-600 text-[9px] mt-1">
                      Source: {bucket.source}
                    </div>
                  </div>
                  <div className="flex gap-1 ml-2">
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
            ))}
          </div>
        </div>
      )}

      {scannedAt && buckets.length === 0 && (
        <div className="text-[11px] text-green-400 text-center py-4">
          No S3 bucket URLs found on this page.
        </div>
      )}

      <div className="text-[10px] text-slate-500 border-t border-slate-700 pt-2 mt-3">
        <div><strong>Detected patterns:</strong></div>
        <div className="text-slate-600">*.s3.amazonaws.com, s3.amazonaws.com/*, regional S3 endpoints</div>
      </div>
    </div>
  );
};

export class S3BucketFinderTool {
  static Component = S3BucketFinder;
}
