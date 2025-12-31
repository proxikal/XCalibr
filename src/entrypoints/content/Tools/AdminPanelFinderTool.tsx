import React, { useState, useRef } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faSearch, faCheckCircle, faTimesCircle, faExternalLinkAlt, faStop, faDownload, faFilter } from '@fortawesome/free-solid-svg-icons';

export type AdminPanelFinderData = {
  baseUrl?: string;
  results?: AdminPathResult[];
  isRunning?: boolean;
  progress?: number;
  scannedAt?: number;
  customPaths?: string;
  delay?: number;
  filterCategory?: PathCategory | 'all';
  concurrent?: number;
};

type PathCategory = 'cms' | 'database' | 'api' | 'framework' | 'generic' | 'hosting' | 'security';

type AdminPathResult = {
  path: string;
  status: number;
  exists: boolean;
  redirectUrl?: string;
  category: PathCategory;
  contentHints?: string[];
};

type Props = {
  data: AdminPanelFinderData | undefined;
  onChange: (data: AdminPanelFinderData) => void;
};

type AdminPath = {
  path: string;
  category: PathCategory;
};

// 200+ admin paths organized by category
const ADMIN_PATHS: AdminPath[] = [
  // === Generic Admin Panels ===
  { path: '/admin', category: 'generic' },
  { path: '/administrator', category: 'generic' },
  { path: '/admin.php', category: 'generic' },
  { path: '/admin.html', category: 'generic' },
  { path: '/admin.asp', category: 'generic' },
  { path: '/admin.aspx', category: 'generic' },
  { path: '/admin.jsp', category: 'generic' },
  { path: '/admin/', category: 'generic' },
  { path: '/adm', category: 'generic' },
  { path: '/login', category: 'generic' },
  { path: '/login.php', category: 'generic' },
  { path: '/login.html', category: 'generic' },
  { path: '/signin', category: 'generic' },
  { path: '/auth', category: 'generic' },
  { path: '/auth/login', category: 'generic' },
  { path: '/authenticate', category: 'generic' },
  { path: '/dashboard', category: 'generic' },
  { path: '/panel', category: 'generic' },
  { path: '/controlpanel', category: 'generic' },
  { path: '/control-panel', category: 'generic' },
  { path: '/backend', category: 'generic' },
  { path: '/manage', category: 'generic' },
  { path: '/management', category: 'generic' },
  { path: '/manager', category: 'generic' },
  { path: '/admin/login', category: 'generic' },
  { path: '/admin/index.php', category: 'generic' },
  { path: '/user/login', category: 'generic' },
  { path: '/secure', category: 'generic' },
  { path: '/portal', category: 'generic' },
  { path: '/webadmin', category: 'generic' },
  { path: '/siteadmin', category: 'generic' },
  { path: '/site-admin', category: 'generic' },
  { path: '/moderator', category: 'generic' },
  { path: '/supervisor', category: 'generic' },
  { path: '/system', category: 'generic' },
  { path: '/system/admin', category: 'generic' },
  { path: '/console', category: 'generic' },
  { path: '/config', category: 'generic' },
  { path: '/settings', category: 'generic' },
  { path: '/setup', category: 'generic' },
  { path: '/install', category: 'generic' },
  { path: '/installer', category: 'generic' },
  { path: '/member', category: 'generic' },
  { path: '/members', category: 'generic' },
  { path: '/account', category: 'generic' },
  { path: '/accounts', category: 'generic' },
  { path: '/user', category: 'generic' },
  { path: '/users', category: 'generic' },
  { path: '/staff', category: 'generic' },
  { path: '/editor', category: 'generic' },
  { path: '/webmaster', category: 'generic' },
  { path: '/superuser', category: 'generic' },
  { path: '/root', category: 'generic' },
  { path: '/private', category: 'generic' },
  { path: '/internal', category: 'generic' },
  { path: '/intranet', category: 'generic' },
  { path: '/backoffice', category: 'generic' },
  { path: '/back-office', category: 'generic' },
  { path: '/office', category: 'generic' },

  // === CMS Specific ===
  { path: '/wp-admin', category: 'cms' },
  { path: '/wp-login.php', category: 'cms' },
  { path: '/wp-admin/admin.php', category: 'cms' },
  { path: '/wordpress/wp-admin', category: 'cms' },
  { path: '/blog/wp-admin', category: 'cms' },
  { path: '/joomla/administrator', category: 'cms' },
  { path: '/administrator/index.php', category: 'cms' },
  { path: '/drupal/admin', category: 'cms' },
  { path: '/drupal/user/login', category: 'cms' },
  { path: '/user/login', category: 'cms' },
  { path: '/magento/admin', category: 'cms' },
  { path: '/index.php/admin', category: 'cms' },
  { path: '/typo3', category: 'cms' },
  { path: '/typo3/login', category: 'cms' },
  { path: '/umbraco', category: 'cms' },
  { path: '/umbraco/login', category: 'cms' },
  { path: '/sitefinity', category: 'cms' },
  { path: '/sitecore', category: 'cms' },
  { path: '/sitecore/login', category: 'cms' },
  { path: '/kentico', category: 'cms' },
  { path: '/cms', category: 'cms' },
  { path: '/cms/admin', category: 'cms' },
  { path: '/ghost', category: 'cms' },
  { path: '/ghost/signin', category: 'cms' },
  { path: '/shopify/admin', category: 'cms' },
  { path: '/woocommerce', category: 'cms' },
  { path: '/prestashop/admin', category: 'cms' },
  { path: '/opencart/admin', category: 'cms' },
  { path: '/bitrix/admin', category: 'cms' },
  { path: '/modx/manager', category: 'cms' },
  { path: '/concrete5/index.php/login', category: 'cms' },
  { path: '/strapi/admin', category: 'cms' },
  { path: '/directus/admin', category: 'cms' },
  { path: '/keystone', category: 'cms' },

  // === Database Administration ===
  { path: '/phpmyadmin', category: 'database' },
  { path: '/phpMyAdmin', category: 'database' },
  { path: '/pma', category: 'database' },
  { path: '/myadmin', category: 'database' },
  { path: '/mysql', category: 'database' },
  { path: '/mysql-admin', category: 'database' },
  { path: '/db', category: 'database' },
  { path: '/database', category: 'database' },
  { path: '/dbadmin', category: 'database' },
  { path: '/adminer', category: 'database' },
  { path: '/adminer.php', category: 'database' },
  { path: '/pgadmin', category: 'database' },
  { path: '/phppgadmin', category: 'database' },
  { path: '/mongodb', category: 'database' },
  { path: '/mongo-express', category: 'database' },
  { path: '/redis', category: 'database' },
  { path: '/redis-commander', category: 'database' },
  { path: '/elasticsearch', category: 'database' },
  { path: '/_plugin/head', category: 'database' },
  { path: '/kibana', category: 'database' },
  { path: '/couchdb', category: 'database' },
  { path: '/_utils', category: 'database' },
  { path: '/rockmongo', category: 'database' },
  { path: '/sql', category: 'database' },
  { path: '/sqlweb', category: 'database' },

  // === Hosting Control Panels ===
  { path: '/cpanel', category: 'hosting' },
  { path: '/cPanel', category: 'hosting' },
  { path: '/whm', category: 'hosting' },
  { path: '/webmail', category: 'hosting' },
  { path: '/plesk', category: 'hosting' },
  { path: '/directadmin', category: 'hosting' },
  { path: '/ispconfig', category: 'hosting' },
  { path: '/virtualmin', category: 'hosting' },
  { path: '/webmin', category: 'hosting' },
  { path: '/cloudpanel', category: 'hosting' },
  { path: '/hestia', category: 'hosting' },
  { path: '/froxlor', category: 'hosting' },
  { path: '/vestacp', category: 'hosting' },
  { path: '/ajenti', category: 'hosting' },
  { path: '/cockpit', category: 'hosting' },
  { path: '/zentyal', category: 'hosting' },

  // === Framework Specific ===
  { path: '/rails/info', category: 'framework' },
  { path: '/rails/mailers', category: 'framework' },
  { path: '/sidekiq', category: 'framework' },
  { path: '/resque', category: 'framework' },
  { path: '/django-admin', category: 'framework' },
  { path: '/django/admin', category: 'framework' },
  { path: '/laravel', category: 'framework' },
  { path: '/laravel-admin', category: 'framework' },
  { path: '/nova', category: 'framework' },
  { path: '/filament', category: 'framework' },
  { path: '/telescope', category: 'framework' },
  { path: '/horizon', category: 'framework' },
  { path: '/symfony', category: 'framework' },
  { path: '/_profiler', category: 'framework' },
  { path: '/spring-boot', category: 'framework' },
  { path: '/actuator', category: 'framework' },
  { path: '/actuator/health', category: 'framework' },
  { path: '/swagger', category: 'framework' },
  { path: '/swagger-ui', category: 'framework' },
  { path: '/swagger-ui.html', category: 'framework' },
  { path: '/api-docs', category: 'framework' },
  { path: '/docs', category: 'framework' },
  { path: '/redoc', category: 'framework' },
  { path: '/graphql', category: 'framework' },
  { path: '/graphiql', category: 'framework' },
  { path: '/playground', category: 'framework' },
  { path: '/express-status', category: 'framework' },
  { path: '/next', category: 'framework' },
  { path: '/_next', category: 'framework' },
  { path: '/nuxt', category: 'framework' },
  { path: '/.nuxt', category: 'framework' },

  // === API Endpoints ===
  { path: '/api', category: 'api' },
  { path: '/api/v1', category: 'api' },
  { path: '/api/v2', category: 'api' },
  { path: '/api/admin', category: 'api' },
  { path: '/api/users', category: 'api' },
  { path: '/api/auth', category: 'api' },
  { path: '/api/login', category: 'api' },
  { path: '/api/config', category: 'api' },
  { path: '/api/settings', category: 'api' },
  { path: '/rest', category: 'api' },
  { path: '/rest/api', category: 'api' },
  { path: '/v1', category: 'api' },
  { path: '/v2', category: 'api' },
  { path: '/oauth', category: 'api' },
  { path: '/oauth2', category: 'api' },
  { path: '/token', category: 'api' },
  { path: '/jwt', category: 'api' },
  { path: '/auth/token', category: 'api' },
  { path: '/.well-known', category: 'api' },
  { path: '/openapi.json', category: 'api' },
  { path: '/openapi.yaml', category: 'api' },

  // === Security / DevOps ===
  { path: '/jenkins', category: 'security' },
  { path: '/jenkins/login', category: 'security' },
  { path: '/hudson', category: 'security' },
  { path: '/gitlab', category: 'security' },
  { path: '/gitlab/users/sign_in', category: 'security' },
  { path: '/gitea', category: 'security' },
  { path: '/gogs', category: 'security' },
  { path: '/bamboo', category: 'security' },
  { path: '/teamcity', category: 'security' },
  { path: '/circleci', category: 'security' },
  { path: '/travis', category: 'security' },
  { path: '/sonar', category: 'security' },
  { path: '/sonarqube', category: 'security' },
  { path: '/grafana', category: 'security' },
  { path: '/prometheus', category: 'security' },
  { path: '/nagios', category: 'security' },
  { path: '/zabbix', category: 'security' },
  { path: '/icinga', category: 'security' },
  { path: '/splunk', category: 'security' },
  { path: '/graylog', category: 'security' },
  { path: '/logstash', category: 'security' },
  { path: '/vault', category: 'security' },
  { path: '/consul', category: 'security' },
  { path: '/nomad', category: 'security' },
  { path: '/traefik', category: 'security' },
  { path: '/portainer', category: 'security' },
  { path: '/rancher', category: 'security' },
  { path: '/kubernetes', category: 'security' },
  { path: '/k8s', category: 'security' },
  { path: '/argo', category: 'security' },
  { path: '/argocd', category: 'security' },
  { path: '/flux', category: 'security' },
  { path: '/harbor', category: 'security' },
  { path: '/nexus', category: 'security' },
  { path: '/artifactory', category: 'security' },
  { path: '/docker', category: 'security' },
  { path: '/registry', category: 'security' },
  { path: '/awx', category: 'security' },
  { path: '/ansible', category: 'security' },
  { path: '/puppet', category: 'security' },
  { path: '/chef', category: 'security' },
  { path: '/terraform', category: 'security' },
  { path: '/pulumi', category: 'security' }
];

const CATEGORY_COLORS: Record<PathCategory, { bg: string; text: string }> = {
  generic: { bg: 'bg-slate-700/50', text: 'text-slate-300' },
  cms: { bg: 'bg-blue-900/50', text: 'text-blue-300' },
  database: { bg: 'bg-purple-900/50', text: 'text-purple-300' },
  hosting: { bg: 'bg-green-900/50', text: 'text-green-300' },
  framework: { bg: 'bg-orange-900/50', text: 'text-orange-300' },
  api: { bg: 'bg-cyan-900/50', text: 'text-cyan-300' },
  security: { bg: 'bg-red-900/50', text: 'text-red-300' }
};

const AdminPanelFinder: React.FC<Props> = ({ data, onChange }) => {
  const baseUrl = data?.baseUrl ?? '';
  const results = data?.results ?? [];
  const isRunning = data?.isRunning ?? false;
  const progress = data?.progress ?? 0;
  const scannedAt = data?.scannedAt;
  const customPaths = data?.customPaths ?? '';
  const delay = data?.delay ?? 50;
  const filterCategory = data?.filterCategory ?? 'all';
  const concurrent = data?.concurrent ?? 5;

  const [showCustom, setShowCustom] = useState(false);
  const abortRef = useRef(false);

  const handleUseCurrentDomain = () => {
    const url = new URL(window.location.href);
    onChange({ ...data, baseUrl: url.origin });
  };

  const handleScan = async () => {
    if (!baseUrl.trim()) return;

    abortRef.current = false;
    onChange({ ...data, isRunning: true, results: [], progress: 0 });

    const pathsToScan: AdminPath[] = customPaths.trim()
      ? customPaths.split('\n').map(p => ({ path: p.trim(), category: 'generic' as PathCategory })).filter(p => p.path)
      : ADMIN_PATHS;

    const foundResults: AdminPathResult[] = [];
    const total = pathsToScan.length;

    // Process in batches for concurrency
    for (let i = 0; i < pathsToScan.length; i += concurrent) {
      if (abortRef.current) break;

      const batch = pathsToScan.slice(i, i + concurrent);

      const batchResults = await Promise.allSettled(
        batch.map(async ({ path, category }) => {
          const fullUrl = baseUrl.replace(/\/$/, '') + (path.startsWith('/') ? path : '/' + path);

          try {
            const response = await fetch(fullUrl, {
              method: 'HEAD',
              credentials: 'omit'
            });

            const exists = response.status >= 200 && response.status < 400;
            const contentHints: string[] = [];

            // Try to detect content type
            const contentType = response.headers.get('content-type') || '';
            if (contentType.includes('html')) contentHints.push('HTML');
            if (contentType.includes('json')) contentHints.push('JSON');

            return {
              path,
              status: response.status,
              exists,
              redirectUrl: response.redirected ? response.url : undefined,
              category,
              contentHints
            };
          } catch {
            // Try background fetch for CORS issues
            try {
              const bgResponse = await chrome.runtime.sendMessage({
                type: 'xcalibr-fetch-url',
                payload: { url: fullUrl, method: 'HEAD' }
              });

              const exists = bgResponse?.status >= 200 && bgResponse?.status < 400;
              return {
                path,
                status: bgResponse?.status || 0,
                exists,
                category,
                contentHints: []
              };
            } catch {
              return { path, status: 0, exists: false, category, contentHints: [] };
            }
          }
        })
      );

      batchResults.forEach((result) => {
        if (result.status === 'fulfilled') {
          foundResults.push(result.value);
        }
      });

      onChange({
        ...data,
        isRunning: true,
        results: [...foundResults],
        progress: Math.round(((i + concurrent) / total) * 100)
      });

      if (delay > 0) {
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }

    onChange({
      ...data,
      isRunning: false,
      results: foundResults,
      progress: 100,
      scannedAt: Date.now()
    });
  };

  const handleStop = () => {
    abortRef.current = true;
    onChange({ ...data, isRunning: false });
  };

  const exportAsJson = () => {
    const exportData = {
      baseUrl,
      scannedAt: scannedAt ? new Date(scannedAt).toISOString() : null,
      totalPaths: results.length,
      foundPanels: filteredResults.filter(r => r.exists),
      allResults: results
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `admin-panels-${new URL(baseUrl || 'localhost').hostname}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredResults = results.filter(r =>
    filterCategory === 'all' || r.category === filterCategory
  );

  const foundPanels = filteredResults.filter(r => r.exists);
  const notFoundCount = filteredResults.filter(r => !r.exists).length;

  const categoryCounts = results.reduce((acc, r) => {
    if (r.exists) {
      acc[r.category] = (acc[r.category] || 0) + 1;
    }
    return acc;
  }, {} as Record<string, number>);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">Admin Panel Finder</div>
        <div className="flex gap-1">
          {results.length > 0 && (
            <button
              onClick={exportAsJson}
              className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
              title="Export as JSON"
            >
              <FontAwesomeIcon icon={faDownload} className="w-2.5 h-2.5" />
            </button>
          )}
          <button
            onClick={handleUseCurrentDomain}
            className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
          >
            Current Domain
          </button>
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Scans {ADMIN_PATHS.length}+ admin paths across 7 categories.
      </div>

      <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
        <label className="text-[9px] text-slate-500 mb-1 block">Target URL</label>
        <input
          type="url"
          value={baseUrl}
          onChange={(e) => onChange({ ...data, baseUrl: e.target.value })}
          placeholder="https://example.com"
          className="w-full rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        />
      </div>

      <div className="flex gap-2 mb-3 flex-wrap">
        <button
          onClick={() => setShowCustom(!showCustom)}
          className="rounded bg-slate-800 px-2 py-1 text-[9px] text-slate-300 hover:bg-slate-700 transition-colors border border-slate-700"
        >
          {showCustom ? 'Hide' : 'Custom'}
        </button>
        <div className="flex items-center gap-1">
          <label className="text-[9px] text-slate-500">Delay:</label>
          <input
            type="number"
            value={delay}
            onChange={(e) => onChange({ ...data, delay: parseInt(e.target.value) || 0 })}
            className="w-12 rounded bg-slate-800 text-slate-200 text-[9px] px-1 py-0.5 border border-slate-700"
            min={0}
            max={5000}
          />
          <span className="text-[9px] text-slate-600">ms</span>
        </div>
        <div className="flex items-center gap-1">
          <label className="text-[9px] text-slate-500">Concurrent:</label>
          <input
            type="number"
            value={concurrent}
            onChange={(e) => onChange({ ...data, concurrent: Math.max(1, Math.min(20, parseInt(e.target.value) || 5)) })}
            className="w-10 rounded bg-slate-800 text-slate-200 text-[9px] px-1 py-0.5 border border-slate-700"
            min={1}
            max={20}
          />
        </div>
      </div>

      {showCustom && (
        <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
          <label className="text-[9px] text-slate-500 mb-1 block">Custom Paths (one per line)</label>
          <textarea
            value={customPaths}
            onChange={(e) => onChange({ ...data, customPaths: e.target.value })}
            placeholder="/admin&#10;/login&#10;/dashboard"
            className="w-full rounded bg-slate-800 text-slate-200 text-[9px] px-2 py-1 border border-slate-700 h-16 font-mono"
          />
        </div>
      )}

      <div className="flex gap-2 mb-3">
        {!isRunning ? (
          <button
            onClick={handleScan}
            disabled={!baseUrl.trim()}
            className="flex-1 rounded bg-purple-600/20 border border-purple-500/30 px-2 py-1.5 text-[10px] text-purple-300 hover:bg-purple-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
          >
            <FontAwesomeIcon icon={faSearch} className="w-2.5 h-2.5" />
            Scan Admin Panels
          </button>
        ) : (
          <button
            onClick={handleStop}
            className="flex-1 rounded bg-red-600/20 border border-red-500/30 px-2 py-1.5 text-[10px] text-red-300 hover:bg-red-600/30 transition-colors flex items-center justify-center gap-2"
          >
            <FontAwesomeIcon icon={faStop} className="w-2.5 h-2.5" />
            Stop Scan
          </button>
        )}
      </div>

      {isRunning && (
        <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
          <div className="flex justify-between text-[9px] text-slate-400 mb-1">
            <span>Scanning...</span>
            <span>{progress}%</span>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-1">
            <div className="bg-purple-500 h-1 rounded-full transition-all" style={{ width: `${progress}%` }} />
          </div>
        </div>
      )}

      {/* Category Filter */}
      {results.length > 0 && (
        <div className="flex items-center gap-1 mb-2 flex-wrap">
          <FontAwesomeIcon icon={faFilter} className="w-2.5 h-2.5 text-slate-500" />
          {(['all', 'generic', 'cms', 'database', 'hosting', 'framework', 'api', 'security'] as const).map(cat => {
            const count = cat === 'all' ? foundPanels.length : (categoryCounts[cat] || 0);
            return (
              <button
                key={cat}
                onClick={() => onChange({ ...data, filterCategory: cat })}
                className={`px-1.5 py-0.5 rounded text-[8px] transition-colors ${
                  filterCategory === cat
                    ? 'bg-purple-600/30 text-purple-300 border border-purple-500/50'
                    : 'bg-slate-800 text-slate-400 border border-slate-700 hover:border-slate-500'
                }`}
              >
                {cat === 'all' ? 'All' : cat.charAt(0).toUpperCase() + cat.slice(1)}
                {count > 0 && <span className="ml-0.5 text-green-400">({count})</span>}
              </button>
            );
          })}
        </div>
      )}

      {results.length > 0 && (
        <div className="flex-1 overflow-y-auto space-y-2 min-h-0">
          <div className="flex gap-4 text-[9px]">
            <span className="text-green-400">
              <FontAwesomeIcon icon={faCheckCircle} className="w-2.5 h-2.5 mr-1" />
              Found: {foundPanels.length}
            </span>
            <span className="text-slate-400">
              <FontAwesomeIcon icon={faTimesCircle} className="w-2.5 h-2.5 mr-1" />
              Not Found: {notFoundCount}
            </span>
          </div>

          {foundPanels.length > 0 && (
            <div className="space-y-1">
              {foundPanels.map((result, index) => {
                const catStyle = CATEGORY_COLORS[result.category];
                return (
                  <div key={index} className="rounded border border-green-700/50 bg-green-900/20 p-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 flex-1 min-w-0">
                        <span className="text-green-400 font-medium text-[10px] truncate">{result.path}</span>
                        <span className={`text-[7px] px-1 py-0.5 rounded ${catStyle.bg} ${catStyle.text}`}>
                          {result.category}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0">
                        <span className="text-slate-400 text-[9px]">{result.status}</span>
                        <a
                          href={baseUrl.replace(/\/$/, '') + result.path}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-[9px] text-slate-500 hover:text-slate-300"
                        >
                          <FontAwesomeIcon icon={faExternalLinkAlt} className="w-2.5 h-2.5" />
                        </a>
                      </div>
                    </div>
                    {result.redirectUrl && (
                      <div className="text-slate-500 mt-1 break-all text-[8px]">
                        → {result.redirectUrl}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {scannedAt && (
            <div className="text-[9px] text-slate-500">
              Scanned: {new Date(scannedAt).toLocaleTimeString()}
            </div>
          )}
        </div>
      )}

      {results.length === 0 && !isRunning && (
        <div className="text-[10px] text-slate-500 text-center py-4">
          Enter a target URL and scan for admin panels.
        </div>
      )}

      <div className="text-[8px] text-slate-600 border-t border-slate-700 pt-2 mt-2">
        <strong>Categories:</strong> Generic, CMS, Database, Hosting, Framework, API, Security/DevOps
      </div>
    </div>
  );
};

export class AdminPanelFinderTool {
  static Component = AdminPanelFinder;
}
