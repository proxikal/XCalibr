import React from 'react';
import type { UsernameSearchData, PlatformResult } from './tool-types';

const PLATFORMS = [
  'Twitter',
  'GitHub',
  'Reddit',
  'Instagram',
  'LinkedIn'
];

const UsernameSearchToolComponent = ({
  data,
  onChange,
  onSearch
}: {
  data: UsernameSearchData | undefined;
  onChange: (next: UsernameSearchData) => void;
  onSearch: (username: string) => Promise<void>;
}) => {
  const username = data?.username ?? '';
  const loading = data?.loading ?? false;
  const results = data?.results ?? [];
  const filter = data?.filter ?? 'all';
  const progress = data?.progress;
  const error = data?.error;

  const handleUsernameChange = (value: string) => {
    const cleaned = value.toLowerCase().trim().replace(/[^a-z0-9_-]/g, '');
    onChange({ ...data, username: cleaned });
  };

  const handleSearch = async () => {
    if (!username || loading) return;
    await onSearch(username);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && username) {
      handleSearch();
    }
  };

  const handleFilterChange = (newFilter: 'all' | 'found' | 'not_found') => {
    onChange({ ...data, filter: newFilter });
  };

  const handleRetry = () => {
    onChange({ ...data, error: undefined });
    handleSearch();
  };

  const handleExport = () => {
    const exportData = results.map(r => ({
      platform: r.platform,
      url: r.url,
      status: r.status,
      statusCode: r.statusCode
    }));
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `username-search-${username}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredResults = results.filter(r => {
    if (filter === 'all') return true;
    return r.status === filter;
  });

  const foundCount = results.filter(r => r.status === 'found').length;
  const notFoundCount = results.filter(r => r.status === 'not_found').length;
  const errorCount = results.filter(r => r.status === 'error').length;

  const getStatusColor = (status: PlatformResult['status']) => {
    switch (status) {
      case 'found':
        return 'xcalibr-bg-green-500/20 xcalibr-border-green-500/50 xcalibr-text-green-400';
      case 'not_found':
        return 'xcalibr-bg-red-500/20 xcalibr-border-red-500/50 xcalibr-text-red-400';
      case 'error':
        return 'xcalibr-bg-yellow-500/20 xcalibr-border-yellow-500/50 xcalibr-text-yellow-400';
    }
  };

  const getStatusIcon = (status: PlatformResult['status']) => {
    switch (status) {
      case 'found':
        return '✓';
      case 'not_found':
        return '✗';
      case 'error':
        return '⚠';
    }
  };

  return (
    <div className="xcalibr-flex xcalibr-flex-col xcalibr-gap-3">
      <div className="xcalibr-flex xcalibr-gap-2">
        <input
          type="text"
          value={username}
          onChange={(e) => handleUsernameChange(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Enter username"
          aria-label="Username to search"
          className="xcalibr-flex-1 xcalibr-bg-[#1e1e1e] xcalibr-border xcalibr-border-[#333] xcalibr-rounded xcalibr-px-2 xcalibr-py-1 xcalibr-text-sm xcalibr-text-white"
          disabled={loading}
        />
        <button
          onClick={handleSearch}
          disabled={!username || loading}
          className="xcalibr-bg-blue-600 xcalibr-text-white xcalibr-px-3 xcalibr-py-1 xcalibr-rounded xcalibr-text-sm hover:xcalibr-bg-blue-700 disabled:xcalibr-opacity-50 disabled:xcalibr-cursor-not-allowed"
        >
          {loading ? 'Searching...' : 'Search'}
        </button>
      </div>

      {loading && progress && (
        <div className="xcalibr-flex xcalibr-flex-col xcalibr-gap-1">
          <div className="xcalibr-text-xs xcalibr-text-gray-400">
            Checking {progress.checked} of {progress.total} platforms...
          </div>
          <div
            role="progressbar"
            aria-valuenow={progress.checked}
            aria-valuemax={progress.total}
            className="xcalibr-h-1 xcalibr-bg-[#333] xcalibr-rounded xcalibr-overflow-hidden"
          >
            <div
              className="xcalibr-h-full xcalibr-bg-blue-500 xcalibr-transition-all"
              style={{ width: `${(progress.checked / progress.total) * 100}%` }}
            />
          </div>
        </div>
      )}

      {error && (
        <div className="xcalibr-bg-red-500/20 xcalibr-border xcalibr-border-red-500/50 xcalibr-rounded xcalibr-p-2 xcalibr-text-sm xcalibr-text-red-400 xcalibr-flex xcalibr-justify-between xcalibr-items-center">
          <span>{error}</span>
          <button
            onClick={handleRetry}
            className="xcalibr-bg-red-600 xcalibr-text-white xcalibr-px-2 xcalibr-py-0.5 xcalibr-rounded xcalibr-text-xs hover:xcalibr-bg-red-700"
          >
            Retry
          </button>
        </div>
      )}

      {results.length === 0 && !loading && !error && (
        <div className="xcalibr-text-sm xcalibr-text-gray-400">
          <div className="xcalibr-mb-2">
            {PLATFORMS.length} platforms will be checked:
          </div>
          <div className="xcalibr-flex xcalibr-flex-wrap xcalibr-gap-1">
            {PLATFORMS.map((platform) => (
              <span
                key={platform}
                className="xcalibr-bg-[#333] xcalibr-px-2 xcalibr-py-0.5 xcalibr-rounded xcalibr-text-xs"
              >
                {platform}
              </span>
            ))}
          </div>
        </div>
      )}

      {results.length > 0 && (
        <>
          <div className="xcalibr-flex xcalibr-items-center xcalibr-justify-between xcalibr-gap-2">
            <div className="xcalibr-text-sm xcalibr-text-gray-300">
              <span className="xcalibr-text-green-400">{foundCount} found</span>
              {' • '}
              <span className="xcalibr-text-red-400">{notFoundCount} not found</span>
              {errorCount > 0 && (
                <>
                  {' • '}
                  <span className="xcalibr-text-yellow-400">{errorCount} errors</span>
                </>
              )}
            </div>
            <button
              onClick={handleExport}
              className="xcalibr-bg-[#333] xcalibr-text-gray-300 xcalibr-px-2 xcalibr-py-0.5 xcalibr-rounded xcalibr-text-xs hover:xcalibr-bg-[#444]"
            >
              Export
            </button>
          </div>

          <div className="xcalibr-flex xcalibr-gap-1">
            {(['all', 'found', 'not_found'] as const).map((filterOption) => (
              <button
                key={filterOption}
                onClick={() => handleFilterChange(filterOption)}
                className={`xcalibr-px-2 xcalibr-py-0.5 xcalibr-rounded xcalibr-text-xs xcalibr-capitalize ${
                  filter === filterOption
                    ? 'xcalibr-bg-blue-600 xcalibr-text-white'
                    : 'xcalibr-bg-[#333] xcalibr-text-gray-400 hover:xcalibr-bg-[#444]'
                }`}
              >
                {filterOption === 'not_found' ? 'Not Found' : filterOption}
              </button>
            ))}
          </div>

          <ul
            role="list"
            className="xcalibr-flex xcalibr-flex-col xcalibr-gap-1 xcalibr-max-h-60 xcalibr-overflow-y-auto"
          >
            {filteredResults.map((result) => (
              <li
                key={result.platform}
                className={`xcalibr-border xcalibr-rounded xcalibr-p-2 ${getStatusColor(result.status)}`}
              >
                <div className="xcalibr-flex xcalibr-items-center xcalibr-justify-between">
                  <div className="xcalibr-flex xcalibr-items-center xcalibr-gap-2">
                    <span className="xcalibr-font-mono xcalibr-text-sm">
                      {getStatusIcon(result.status)}
                    </span>
                    {result.status === 'found' ? (
                      <a
                        href={result.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="xcalibr-font-medium xcalibr-text-sm hover:xcalibr-underline"
                      >
                        {result.platform}
                      </a>
                    ) : (
                      <span className="xcalibr-font-medium xcalibr-text-sm">
                        {result.platform}
                      </span>
                    )}
                  </div>
                  <span className="xcalibr-text-xs xcalibr-opacity-70">
                    {result.statusCode > 0 ? result.statusCode : ''}
                  </span>
                </div>
                <div className="xcalibr-text-xs xcalibr-opacity-70 xcalibr-truncate xcalibr-mt-1">
                  {result.url}
                </div>
                {result.error && (
                  <div className="xcalibr-text-xs xcalibr-text-yellow-400 xcalibr-mt-1">
                    {result.error}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
};

export class UsernameSearchTool {
  static Component = UsernameSearchToolComponent;
}
