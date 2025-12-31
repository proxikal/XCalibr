import React from 'react';
import { WaybackMachineViewerData, WaybackSnapshot } from './tool-types';

type Props = {
  data: WaybackMachineViewerData;
  onChange: (data: WaybackMachineViewerData) => void;
  onSearch: (url: string) => void;
};

const formatTimestamp = (ts: string): string => {
  // Wayback format: YYYYMMDDhhmmss
  if (ts.length < 14) return ts;
  const year = ts.slice(0, 4);
  const month = ts.slice(4, 6);
  const day = ts.slice(6, 8);
  const hour = ts.slice(8, 10);
  const minute = ts.slice(10, 12);
  const date = new Date(`${year}-${month}-${day}T${hour}:${minute}:00`);
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
};

const getYear = (ts: string): string => ts.slice(0, 4);

const buildArchiveUrl = (snapshot: WaybackSnapshot): string => {
  return `https://web.archive.org/web/${snapshot.timestamp}/${snapshot.original}`;
};

export const WaybackMachineViewerTool = ({ data, onChange, onSearch }: Props) => {
  const url = data.url || '';
  const loading = data.loading || false;
  const snapshots = data.snapshots || [];
  const yearFilter = data.yearFilter || '';
  const error = data.error;
  const hasSearched = !!data.searchedAt;

  const filteredSnapshots = yearFilter
    ? snapshots.filter(s => getYear(s.timestamp) === yearFilter)
    : snapshots;

  const years = [...new Set(snapshots.map(s => getYear(s.timestamp)))].sort().reverse();

  const handleSearch = () => {
    if (!url.trim()) return;
    let normalizedUrl = url.trim();
    if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
      normalizedUrl = 'https://' + normalizedUrl;
    }
    onSearch(normalizedUrl);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const oldestSnapshot = snapshots.length > 0
    ? snapshots.reduce((a, b) => a.timestamp < b.timestamp ? a : b)
    : null;

  const newestSnapshot = snapshots.length > 0
    ? snapshots.reduce((a, b) => a.timestamp > b.timestamp ? a : b)
    : null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', padding: '8px' }}>
      <div style={{ display: 'flex', gap: '8px' }}>
        <input
          type="text"
          value={url}
          onChange={e => onChange({ ...data, url: e.target.value })}
          placeholder="Enter URL or domain"
          style={{
            flex: 1,
            padding: '8px 12px',
            border: '1px solid #555',
            borderRadius: '4px',
            backgroundColor: '#2a2a2a',
            color: '#fff',
            fontSize: '14px'
          }}
          onKeyDown={e => {
            if (e.key === 'Enter') handleSearch();
          }}
        />
        <button
          onClick={handleSearch}
          disabled={!url.trim() || loading}
          style={{
            padding: '8px 16px',
            backgroundColor: loading ? '#555' : '#4a9eff',
            color: '#fff',
            border: 'none',
            borderRadius: '4px',
            cursor: loading || !url.trim() ? 'not-allowed' : 'pointer',
            opacity: loading || !url.trim() ? 0.6 : 1
          }}
        >
          {loading ? 'Searching...' : 'Search'}
        </button>
      </div>

      {loading && (
        <div style={{ textAlign: 'center', padding: '20px', color: '#888' }}>
          <div className="animate-spin" style={{
            width: '24px',
            height: '24px',
            border: '2px solid #555',
            borderTopColor: '#4a9eff',
            borderRadius: '50%',
            margin: '0 auto 10px',
            animation: 'spin 1s linear infinite'
          }} />
          Fetching snapshots from Wayback Machine...
        </div>
      )}

      {error && (
        <div style={{
          padding: '12px',
          backgroundColor: 'rgba(255, 100, 100, 0.1)',
          border: '1px solid #f66',
          borderRadius: '4px',
          color: '#f88'
        }}>
          {error}
        </div>
      )}

      {hasSearched && !loading && !error && snapshots.length === 0 && (
        <div style={{
          padding: '20px',
          textAlign: 'center',
          color: '#888',
          backgroundColor: '#1e1e1e',
          borderRadius: '4px'
        }}>
          No snapshots found for this URL in the Wayback Machine.
        </div>
      )}

      {hasSearched && !loading && snapshots.length > 0 && (
        <>
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: '8px 12px',
            backgroundColor: '#1e1e1e',
            borderRadius: '4px'
          }}>
            <div>
              <strong>{snapshots.length}</strong> snapshot{snapshots.length !== 1 ? 's' : ''} found
              {oldestSnapshot && newestSnapshot && (
                <span style={{ color: '#888', marginLeft: '8px' }}>
                  ({getYear(oldestSnapshot.timestamp)} - {getYear(newestSnapshot.timestamp)})
                </span>
              )}
            </div>
            {years.length > 1 && (
              <select
                value={yearFilter}
                onChange={e => onChange({ ...data, yearFilter: e.target.value })}
                style={{
                  padding: '4px 8px',
                  backgroundColor: '#2a2a2a',
                  color: '#fff',
                  border: '1px solid #555',
                  borderRadius: '4px'
                }}
              >
                <option value="">All years</option>
                {years.map(y => (
                  <option key={y} value={y}>{y}</option>
                ))}
              </select>
            )}
          </div>

          <div style={{
            maxHeight: '400px',
            overflowY: 'auto',
            border: '1px solid #333',
            borderRadius: '4px'
          }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ backgroundColor: '#1e1e1e', position: 'sticky', top: 0 }}>
                  <th style={{ padding: '8px 12px', textAlign: 'left', borderBottom: '1px solid #333' }}>Date</th>
                  <th style={{ padding: '8px 12px', textAlign: 'left', borderBottom: '1px solid #333' }}>Status</th>
                  <th style={{ padding: '8px 12px', textAlign: 'left', borderBottom: '1px solid #333' }}>Type</th>
                  <th style={{ padding: '8px 12px', textAlign: 'left', borderBottom: '1px solid #333' }}>URL</th>
                  <th style={{ padding: '8px 12px', textAlign: 'center', borderBottom: '1px solid #333' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredSnapshots.map((snapshot, idx) => {
                  const archiveUrl = buildArchiveUrl(snapshot);
                  const statusColor = snapshot.statuscode.startsWith('2') ? '#4ade80'
                    : snapshot.statuscode.startsWith('3') ? '#fbbf24'
                    : '#f87171';
                  return (
                    <tr key={idx} style={{ borderBottom: '1px solid #333' }}>
                      <td style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                        {formatTimestamp(snapshot.timestamp)}
                      </td>
                      <td style={{ padding: '8px 12px' }}>
                        <span style={{
                          color: statusColor,
                          fontFamily: 'monospace'
                        }}>
                          {snapshot.statuscode}
                        </span>
                      </td>
                      <td style={{ padding: '8px 12px', color: '#888', fontSize: '12px' }}>
                        {snapshot.mimetype.split('/').pop() || snapshot.mimetype}
                      </td>
                      <td style={{
                        padding: '8px 12px',
                        maxWidth: '200px',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                        color: '#888',
                        fontSize: '12px'
                      }} title={snapshot.original}>
                        {snapshot.original}
                      </td>
                      <td style={{ padding: '8px 12px', textAlign: 'center' }}>
                        <div style={{ display: 'flex', gap: '4px', justifyContent: 'center' }}>
                          <a
                            href={archiveUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            style={{
                              padding: '4px 8px',
                              backgroundColor: '#4a9eff',
                              color: '#fff',
                              borderRadius: '4px',
                              textDecoration: 'none',
                              fontSize: '12px'
                            }}
                          >
                            View
                          </a>
                          <button
                            onClick={() => copyToClipboard(archiveUrl)}
                            title="Copy archive URL"
                            style={{
                              padding: '4px 8px',
                              backgroundColor: '#444',
                              color: '#fff',
                              border: 'none',
                              borderRadius: '4px',
                              cursor: 'pointer',
                              fontSize: '12px'
                            }}
                          >
                            Copy
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {yearFilter && filteredSnapshots.length !== snapshots.length && (
            <div style={{ textAlign: 'center', color: '#888', fontSize: '13px' }}>
              Showing {filteredSnapshots.length} of {snapshots.length} snapshots for {yearFilter}
            </div>
          )}
        </>
      )}
    </div>
  );
};
