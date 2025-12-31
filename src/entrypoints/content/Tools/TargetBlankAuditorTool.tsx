import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faSearch, faExternalLinkAlt, faExclamationTriangle, faCheckCircle, faCopy, faWrench } from '@fortawesome/free-solid-svg-icons';

export type VulnerableLink = {
  href: string;
  text: string;
  hasNoopener: boolean;
  hasNoreferrer: boolean;
  element?: string;
};

export type TargetBlankAuditorData = {
  vulnerableLinks?: VulnerableLink[];
  totalLinks?: number;
  totalBlankLinks?: number;
  scannedAt?: number;
  error?: string;
};

type Props = {
  data: TargetBlankAuditorData | undefined;
  onChange: (data: TargetBlankAuditorData) => void;
};

const TargetBlankAuditor: React.FC<Props> = ({ data, onChange }) => {
  const vulnerableLinks = data?.vulnerableLinks ?? [];
  const totalLinks = data?.totalLinks ?? 0;
  const totalBlankLinks = data?.totalBlankLinks ?? 0;
  const scannedAt = data?.scannedAt;
  const error = data?.error;
  const [scanning, setScanning] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const scanPage = () => {
    setScanning(true);
    try {
      const allLinks = document.querySelectorAll('a');
      const blankLinks = document.querySelectorAll('a[target="_blank"]');
      const vulnerable: VulnerableLink[] = [];

      blankLinks.forEach((link) => {
        const anchor = link as HTMLAnchorElement;
        const rel = anchor.getAttribute('rel') || '';
        const hasNoopener = rel.includes('noopener');
        const hasNoreferrer = rel.includes('noreferrer');

        // Link is vulnerable if it's missing both noopener and noreferrer
        if (!hasNoopener || !hasNoreferrer) {
          vulnerable.push({
            href: anchor.href,
            text: anchor.textContent?.trim().substring(0, 100) || '[no text]',
            hasNoopener,
            hasNoreferrer,
            element: anchor.outerHTML.substring(0, 200)
          });
        }
      });

      onChange({
        vulnerableLinks: vulnerable,
        totalLinks: allLinks.length,
        totalBlankLinks: blankLinks.length,
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

  const fixLink = (link: VulnerableLink, index: number) => {
    // Find and fix the actual link in the DOM
    const anchors = document.querySelectorAll(`a[href="${CSS.escape(link.href)}"][target="_blank"]`);
    anchors.forEach((anchor) => {
      const currentRel = anchor.getAttribute('rel') || '';
      const newRel = ['noopener', 'noreferrer', ...currentRel.split(' ').filter(r => r && r !== 'noopener' && r !== 'noreferrer')].join(' ');
      anchor.setAttribute('rel', newRel);
    });

    // Update state to reflect the fix
    const updatedLinks = [...vulnerableLinks];
    updatedLinks[index] = { ...link, hasNoopener: true, hasNoreferrer: true };
    // Remove from vulnerable list since it's now fixed
    updatedLinks.splice(index, 1);
    onChange({ ...data, vulnerableLinks: updatedLinks });
  };

  const fixAllLinks = () => {
    vulnerableLinks.forEach((link) => {
      const anchors = document.querySelectorAll(`a[href="${CSS.escape(link.href)}"][target="_blank"]`);
      anchors.forEach((anchor) => {
        const currentRel = anchor.getAttribute('rel') || '';
        const newRel = ['noopener', 'noreferrer', ...currentRel.split(' ').filter(r => r && r !== 'noopener' && r !== 'noreferrer')].join(' ');
        anchor.setAttribute('rel', newRel);
      });
    });
    onChange({ ...data, vulnerableLinks: [] });
  };

  const safeCount = totalBlankLinks - vulnerableLinks.length;

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">Target Blank Auditor</div>
        <div className="flex gap-2">
          {vulnerableLinks.length > 0 && (
            <button
              onClick={fixAllLinks}
              className="rounded bg-green-600/20 border border-green-500/30 px-2 py-1 text-[10px] text-green-300 hover:bg-green-600/30 transition-colors"
            >
              Fix All
            </button>
          )}
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Finds links with <code className="bg-slate-800 px-1 rounded">target="_blank"</code> that are missing
        <code className="bg-slate-800 px-1 rounded ml-1">rel="noopener noreferrer"</code> (tabnabbing vulnerability).
      </div>

      <button
        onClick={scanPage}
        disabled={scanning}
        className="w-full rounded bg-blue-600/20 border border-blue-500/30 px-2 py-1.5 text-[11px] text-blue-300 hover:bg-blue-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2 mb-3"
      >
        <FontAwesomeIcon icon={faSearch} className="w-3 h-3" />
        {scanning ? 'Scanning...' : 'Audit Links'}
      </button>

      {error && (
        <div className="text-red-400 text-[10px] bg-red-900/20 border border-red-700/50 p-2 rounded mb-3">
          {error}
        </div>
      )}

      {/* Statistics */}
      {scannedAt && (
        <div className="grid grid-cols-3 gap-2 mb-3">
          <div className="rounded border border-slate-700 bg-slate-800/50 p-2 text-center">
            <div className="text-slate-200 font-bold text-[11px]">{totalLinks}</div>
            <div className="text-[9px] text-slate-500">Total Links</div>
          </div>
          <div className="rounded border border-slate-700 bg-slate-800/50 p-2 text-center">
            <div className="text-blue-400 font-bold text-[11px]">{totalBlankLinks}</div>
            <div className="text-[9px] text-slate-500">target="_blank"</div>
          </div>
          <div className={`rounded border p-2 text-center ${vulnerableLinks.length > 0 ? 'bg-red-900/30 border-red-700/50' : 'bg-green-900/30 border-green-700/50'}`}>
            <div className={`font-bold text-[11px] ${vulnerableLinks.length > 0 ? 'text-red-400' : 'text-green-400'}`}>
              {vulnerableLinks.length}
            </div>
            <div className="text-[9px] text-slate-500">Vulnerable</div>
          </div>
        </div>
      )}

      {/* Status */}
      {scannedAt && (
        <div className={`rounded border p-2 mb-3 ${vulnerableLinks.length > 0 ? 'bg-yellow-900/30 border-yellow-700/50' : 'bg-green-900/30 border-green-500/50'}`}>
          <div className={`font-medium flex items-center gap-2 text-[11px] ${vulnerableLinks.length > 0 ? 'text-yellow-400' : 'text-green-400'}`}>
            <FontAwesomeIcon icon={vulnerableLinks.length > 0 ? faExclamationTriangle : faCheckCircle} className="w-3 h-3" />
            {vulnerableLinks.length > 0
              ? `${vulnerableLinks.length} link(s) vulnerable to tabnabbing`
              : 'All external links are properly secured'}
          </div>
        </div>
      )}

      {/* Vulnerable Links */}
      <div className="flex-1 overflow-y-auto space-y-2 min-h-0">
        {vulnerableLinks.length > 0 ? (
          vulnerableLinks.map((link, idx) => (
            <div key={idx} className="rounded border border-yellow-700/50 bg-slate-800/50 p-2">
              <div className="flex justify-between items-start">
                <div className="flex-1 min-w-0">
                  <div className="text-slate-200 text-[11px] break-all">
                    {link.text}
                  </div>
                  <div className="text-blue-400 text-[10px] font-mono mt-1 break-all">
                    {link.href}
                  </div>
                  <div className="flex gap-2 mt-1">
                    <span className={`text-[9px] px-1.5 py-0.5 rounded ${link.hasNoopener ? 'bg-green-900/50 text-green-300' : 'bg-red-900/50 text-red-300'}`}>
                      {link.hasNoopener ? 'noopener' : 'missing noopener'}
                    </span>
                    <span className={`text-[9px] px-1.5 py-0.5 rounded ${link.hasNoreferrer ? 'bg-green-900/50 text-green-300' : 'bg-red-900/50 text-red-300'}`}>
                      {link.hasNoreferrer ? 'noreferrer' : 'missing noreferrer'}
                    </span>
                  </div>
                </div>
                <div className="flex gap-1 ml-2 flex-shrink-0">
                  <button
                    onClick={() => fixLink(link, idx)}
                    className="text-[9px] text-slate-500 hover:text-green-400 p-1"
                    title="Fix this link"
                  >
                    <FontAwesomeIcon icon={faWrench} className="w-2.5 h-2.5" />
                  </button>
                  <a
                    href={link.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[9px] text-slate-500 hover:text-blue-400 p-1"
                    title="Open link"
                  >
                    <FontAwesomeIcon icon={faExternalLinkAlt} className="w-2.5 h-2.5" />
                  </a>
                  <button
                    onClick={() => copyToClipboard(link.href, idx)}
                    className="text-[9px] text-slate-500 hover:text-slate-300 p-1"
                    title="Copy URL"
                  >
                    <FontAwesomeIcon icon={faCopy} className="w-2.5 h-2.5" />
                  </button>
                </div>
              </div>
              {copiedIndex === idx && (
                <span className="text-green-400 text-[10px]">Copied!</span>
              )}
            </div>
          ))
        ) : scannedAt ? (
          <div className="text-[11px] text-green-400 text-center py-4">
            No vulnerable links found.
          </div>
        ) : (
          <div className="text-[11px] text-slate-500 text-center py-4">
            Click "Audit Links" to scan the page.
          </div>
        )}
      </div>

      {scannedAt && (
        <div className="text-[10px] text-slate-500 mt-3 pt-2 border-t border-slate-700">
          Last scanned: {new Date(scannedAt).toLocaleTimeString()}
        </div>
      )}

      <div className="text-[10px] text-slate-500 border-t border-slate-700 pt-2 mt-2">
        <div><strong>About tabnabbing:</strong></div>
        <div className="text-slate-600">
          Links with target="_blank" without rel="noopener" allow the new page to access window.opener,
          potentially redirecting the original page to a phishing site.
        </div>
      </div>
    </div>
  );
};

export class TargetBlankAuditorTool {
  static Component = TargetBlankAuditor;
}
