import React from 'react';
import type { SubdomainFinderData } from './tool-types';

// Validate domain format
const isValidDomain = (domain: string): boolean => {
  const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/;
  return domainRegex.test(domain);
};

const SubdomainFinderToolComponent = ({
  data,
  onChange,
  onFind
}: {
  data: SubdomainFinderData | undefined;
  onChange: (next: SubdomainFinderData) => void;
  onFind: (domain: string) => Promise<void>;
}) => {
  const domain = data?.domain ?? '';
  const loading = data?.loading ?? false;
  const subdomains = data?.subdomains ?? [];
  const filter = data?.filter ?? '';
  const searchedAt = data?.searchedAt;
  const error = data?.error;

  const handleDomainChange = (value: string) => {
    onChange({ ...data, domain: value.trim(), error: undefined });
  };

  const handleFilterChange = (value: string) => {
    onChange({ ...data, filter: value });
  };

  const handleFind = async () => {
    if (!domain || !isValidDomain(domain) || loading) return;
    await onFind(domain);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && domain && isValidDomain(domain)) {
      handleFind();
    }
  };

  const handleClear = () => {
    onChange({});
  };

  const handleCopyAll = async () => {
    const text = filteredSubdomains.join('\n');
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const textArea = document.createElement('textarea');
      textArea.value = text;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
    }
  };

  const isDomainValid = domain.length > 0 && isValidDomain(domain);
  const hasResults = searchedAt !== undefined;

  const filteredSubdomains = filter
    ? subdomains.filter(sub => sub.toLowerCase().includes(filter.toLowerCase()))
    : subdomains;

  return (
    <div className="xcalibr-flex xcalibr-flex-col xcalibr-gap-3">
      <div className="xcalibr-flex xcalibr-gap-2">
        <input
          type="text"
          value={domain}
          onChange={(e) => handleDomainChange(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Enter domain (e.g., example.com)"
          className="xcalibr-flex-1 xcalibr-bg-[#1e1e1e] xcalibr-border xcalibr-border-[#333] xcalibr-rounded xcalibr-px-2 xcalibr-py-1 xcalibr-text-sm xcalibr-text-white"
          disabled={loading}
        />
        <button
          onClick={handleFind}
          disabled={!isDomainValid || loading}
          className="xcalibr-bg-blue-600 xcalibr-text-white xcalibr-px-3 xcalibr-py-1 xcalibr-rounded xcalibr-text-sm hover:xcalibr-bg-blue-700 disabled:xcalibr-opacity-50 disabled:xcalibr-cursor-not-allowed"
        >
          {loading ? 'Searching...' : 'Find'}
        </button>
      </div>

      {domain && !isDomainValid && (
        <div className="xcalibr-text-xs xcalibr-text-yellow-400">
          Please enter a valid domain
        </div>
      )}

      {error && (
        <div className="xcalibr-bg-red-500/20 xcalibr-border xcalibr-border-red-500/50 xcalibr-rounded xcalibr-p-2 xcalibr-text-sm xcalibr-text-red-400">
          {error}
        </div>
      )}

      {hasResults && subdomains.length === 0 && !error && (
        <div className="xcalibr-bg-yellow-500/20 xcalibr-border xcalibr-border-yellow-500/50 xcalibr-rounded xcalibr-p-3 xcalibr-text-center">
          <div className="xcalibr-text-yellow-400 xcalibr-font-medium">No subdomains found</div>
          <div className="xcalibr-text-xs xcalibr-text-gray-400 xcalibr-mt-1">
            Try a different domain or check if it exists
          </div>
        </div>
      )}

      {hasResults && subdomains.length > 0 && (
        <div className="xcalibr-flex xcalibr-flex-col xcalibr-gap-3">
          <div className="xcalibr-flex xcalibr-justify-between xcalibr-items-center">
            <span className="xcalibr-text-sm xcalibr-text-gray-400">
              Found {subdomains.length} subdomain{subdomains.length !== 1 ? 's' : ''}
            </span>
            <div className="xcalibr-flex xcalibr-gap-2">
              <button
                onClick={handleCopyAll}
                className="xcalibr-text-xs xcalibr-text-gray-500 hover:xcalibr-text-gray-300"
              >
                Copy All
              </button>
              <button
                onClick={handleClear}
                className="xcalibr-text-xs xcalibr-text-gray-500 hover:xcalibr-text-gray-300"
              >
                Clear
              </button>
            </div>
          </div>

          {/* Filter */}
          <input
            type="text"
            value={filter}
            onChange={(e) => handleFilterChange(e.target.value)}
            placeholder="Filter subdomains..."
            className="xcalibr-bg-[#1e1e1e] xcalibr-border xcalibr-border-[#333] xcalibr-rounded xcalibr-px-2 xcalibr-py-1 xcalibr-text-sm xcalibr-text-white"
          />

          {filter && (
            <div className="xcalibr-text-xs xcalibr-text-gray-500">
              Showing {filteredSubdomains.length} of {subdomains.length}
            </div>
          )}

          {/* Subdomain List */}
          <div className="xcalibr-flex xcalibr-flex-col xcalibr-gap-1 xcalibr-max-h-60 xcalibr-overflow-y-auto">
            {filteredSubdomains.map((subdomain, i) => (
              <div
                key={i}
                className="xcalibr-bg-[#1e1e1e] xcalibr-border xcalibr-border-[#333] xcalibr-rounded xcalibr-px-2 xcalibr-py-1 xcalibr-flex xcalibr-justify-between xcalibr-items-center xcalibr-group"
              >
                <span className="xcalibr-text-sm xcalibr-text-white xcalibr-font-mono">
                  {subdomain}
                </span>
                <a
                  href={`https://${subdomain}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="xcalibr-text-xs xcalibr-text-blue-400 xcalibr-opacity-0 group-hover:xcalibr-opacity-100 hover:xcalibr-underline"
                >
                  Open
                </a>
              </div>
            ))}
          </div>
        </div>
      )}

      {!hasResults && !loading && !error && (
        <div className="xcalibr-text-sm xcalibr-text-gray-400 xcalibr-text-center xcalibr-py-4">
          Enter a domain to find its subdomains
        </div>
      )}
    </div>
  );
};

export class SubdomainFinderTool {
  static Component = SubdomainFinderToolComponent;
}
