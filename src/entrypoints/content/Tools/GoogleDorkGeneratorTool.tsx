import React from 'react';
import type { GoogleDorkGeneratorData, DorkTemplate, DorkHistoryEntry } from './tool-types';

// Predefined dork templates
const DORK_TEMPLATES: DorkTemplate[] = [
  // File Discovery
  { name: 'PDF Files', template: 'site:{domain} filetype:pdf', description: 'Find PDF documents', category: 'Files' },
  { name: 'Document Files', template: 'site:{domain} filetype:doc OR filetype:docx', description: 'Find Word documents', category: 'Files' },
  { name: 'Spreadsheets', template: 'site:{domain} filetype:xls OR filetype:xlsx', description: 'Find Excel files', category: 'Files' },
  { name: 'SQL Files', template: 'site:{domain} filetype:sql', description: 'Find SQL dumps', category: 'Files' },
  { name: 'Config Files', template: 'site:{domain} filetype:xml OR filetype:conf OR filetype:ini', description: 'Find configuration files', category: 'Files' },
  { name: 'Log Files', template: 'site:{domain} filetype:log', description: 'Find log files', category: 'Files' },

  // Login & Admin
  { name: 'Login Pages', template: 'site:{domain} inurl:login OR inurl:signin', description: 'Find login pages', category: 'Login' },
  { name: 'Admin Panels', template: 'site:{domain} inurl:admin OR inurl:administrator', description: 'Find admin panels', category: 'Login' },
  { name: 'Dashboard', template: 'site:{domain} inurl:dashboard OR inurl:portal', description: 'Find dashboards', category: 'Login' },
  { name: 'Control Panel', template: 'site:{domain} inurl:cpanel OR inurl:webmail', description: 'Find control panels', category: 'Login' },

  // Sensitive Info
  { name: 'Password Files', template: 'site:{domain} "password" filetype:txt OR filetype:log', description: 'Find password files', category: 'Sensitive' },
  { name: 'API Keys', template: 'site:{domain} "api_key" OR "apikey" OR "api-key"', description: 'Find API keys', category: 'Sensitive' },
  { name: 'Private Keys', template: 'site:{domain} filetype:pem OR filetype:key', description: 'Find private keys', category: 'Sensitive' },
  { name: 'Backup Files', template: 'site:{domain} filetype:bak OR filetype:backup OR filetype:old', description: 'Find backup files', category: 'Sensitive' },

  // Directory Listing
  { name: 'Directory Listing', template: 'site:{domain} intitle:"index of"', description: 'Find open directories', category: 'Directories' },
  { name: 'Parent Directory', template: 'site:{domain} "parent directory"', description: 'Find directory listings', category: 'Directories' },

  // Exposed Data
  { name: 'Error Messages', template: 'site:{domain} "error" OR "exception" OR "warning"', description: 'Find error pages', category: 'Exposed' },
  { name: 'PHP Errors', template: 'site:{domain} "PHP Parse error" OR "PHP Warning"', description: 'Find PHP errors', category: 'Exposed' },
  { name: 'SQL Errors', template: 'site:{domain} "SQL syntax" OR "mysql_fetch"', description: 'Find SQL errors', category: 'Exposed' },

  // Custom
  { name: 'Custom Keyword', template: 'site:{domain} {keyword}', description: 'Search with custom keyword', category: 'Custom' },
  { name: 'URL Contains', template: 'site:{domain} inurl:{keyword}', description: 'URL contains keyword', category: 'Custom' },
  { name: 'Title Contains', template: 'site:{domain} intitle:{keyword}', description: 'Title contains keyword', category: 'Custom' }
];

const CATEGORIES = ['All', 'Files', 'Login', 'Sensitive', 'Directories', 'Exposed', 'Custom'];

const GoogleDorkGeneratorToolComponent = ({
  data,
  onChange
}: {
  data: GoogleDorkGeneratorData | undefined;
  onChange: (next: GoogleDorkGeneratorData) => void;
}) => {
  const domain = data?.domain ?? '';
  const keyword = data?.keyword ?? '';
  const selectedTemplate = data?.selectedTemplate ?? '';
  const generatedQuery = data?.generatedQuery ?? '';
  const history = data?.history ?? [];
  const [selectedCategory, setSelectedCategory] = React.useState('All');
  const [copied, setCopied] = React.useState(false);

  const handleDomainChange = (value: string) => {
    onChange({ ...data, domain: value.trim() });
  };

  const handleKeywordChange = (value: string) => {
    onChange({ ...data, keyword: value });
  };

  const handleTemplateSelect = (templateName: string) => {
    const template = DORK_TEMPLATES.find(t => t.name === templateName);
    if (!template) return;

    let query = template.template;
    if (domain) {
      query = query.replace('{domain}', domain);
    }
    if (keyword) {
      query = query.replace('{keyword}', keyword);
    }

    const newHistory: DorkHistoryEntry[] = [
      { query, timestamp: Date.now() },
      ...history.slice(0, 9)
    ];

    onChange({
      ...data,
      selectedTemplate: templateName,
      generatedQuery: query,
      history: newHistory
    });
  };

  const handleGenerate = () => {
    if (!domain) return;
    const template = DORK_TEMPLATES.find(t => t.name === selectedTemplate);
    if (!template) return;

    let query = template.template;
    query = query.replace('{domain}', domain);
    if (keyword) {
      query = query.replace('{keyword}', keyword);
    }

    const newHistory: DorkHistoryEntry[] = [
      { query, timestamp: Date.now() },
      ...history.slice(0, 9)
    ];

    onChange({
      ...data,
      generatedQuery: query,
      history: newHistory
    });
  };

  const handleCopy = async () => {
    if (!generatedQuery) return;
    try {
      await navigator.clipboard.writeText(generatedQuery);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback for older browsers
      const textArea = document.createElement('textarea');
      textArea.value = generatedQuery;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleSearch = () => {
    if (!generatedQuery) return;
    const url = `https://www.google.com/search?q=${encodeURIComponent(generatedQuery)}`;
    window.open(url, '_blank');
  };

  const handleClear = () => {
    onChange({ history });
  };

  const handleHistorySelect = (query: string) => {
    onChange({ ...data, generatedQuery: query });
  };

  const filteredTemplates = selectedCategory === 'All'
    ? DORK_TEMPLATES
    : DORK_TEMPLATES.filter(t => t.category === selectedCategory);

  return (
    <div className="xcalibr-flex xcalibr-flex-col xcalibr-gap-3">
      {/* Domain Input */}
      <div className="xcalibr-flex xcalibr-flex-col xcalibr-gap-1">
        <label className="xcalibr-text-xs xcalibr-text-gray-400">Target Domain</label>
        <input
          type="text"
          value={domain}
          onChange={(e) => handleDomainChange(e.target.value)}
          placeholder="Enter target domain"
          className="xcalibr-bg-[#1e1e1e] xcalibr-border xcalibr-border-[#333] xcalibr-rounded xcalibr-px-2 xcalibr-py-1 xcalibr-text-sm xcalibr-text-white"
        />
      </div>

      {/* Keyword Input */}
      <div className="xcalibr-flex xcalibr-flex-col xcalibr-gap-1">
        <label className="xcalibr-text-xs xcalibr-text-gray-400">Keyword (optional)</label>
        <input
          type="text"
          value={keyword}
          onChange={(e) => handleKeywordChange(e.target.value)}
          placeholder="password, admin, etc."
          className="xcalibr-bg-[#1e1e1e] xcalibr-border xcalibr-border-[#333] xcalibr-rounded xcalibr-px-2 xcalibr-py-1 xcalibr-text-sm xcalibr-text-white"
        />
      </div>

      {/* Category Filter */}
      <div className="xcalibr-flex xcalibr-gap-1 xcalibr-flex-wrap">
        {CATEGORIES.map(cat => (
          <button
            key={cat}
            onClick={() => setSelectedCategory(cat)}
            className={`xcalibr-px-2 xcalibr-py-0.5 xcalibr-rounded xcalibr-text-xs ${
              selectedCategory === cat
                ? 'xcalibr-bg-blue-600 xcalibr-text-white'
                : 'xcalibr-bg-[#333] xcalibr-text-gray-400 hover:xcalibr-bg-[#444]'
            }`}
          >
            {cat}
          </button>
        ))}
      </div>

      {/* Template Selection */}
      <div className="xcalibr-flex xcalibr-flex-col xcalibr-gap-1 xcalibr-max-h-40 xcalibr-overflow-y-auto">
        <label className="xcalibr-text-xs xcalibr-text-gray-400">Select Template</label>
        {filteredTemplates.map(template => (
          <button
            key={template.name}
            onClick={() => handleTemplateSelect(template.name)}
            disabled={!domain}
            className={`xcalibr-text-left xcalibr-p-2 xcalibr-rounded xcalibr-text-xs ${
              selectedTemplate === template.name
                ? 'xcalibr-bg-blue-600/30 xcalibr-border xcalibr-border-blue-500'
                : 'xcalibr-bg-[#1e1e1e] xcalibr-border xcalibr-border-[#333] hover:xcalibr-border-[#555]'
            } ${!domain ? 'xcalibr-opacity-50 xcalibr-cursor-not-allowed' : ''}`}
          >
            <div className="xcalibr-text-white xcalibr-font-medium">{template.name}</div>
            <div className="xcalibr-text-gray-500">{template.description}</div>
          </button>
        ))}
      </div>

      {/* Generated Query */}
      {generatedQuery && (
        <div className="xcalibr-flex xcalibr-flex-col xcalibr-gap-2">
          <div className="xcalibr-flex xcalibr-justify-between xcalibr-items-center">
            <label className="xcalibr-text-xs xcalibr-text-gray-400">Generated Query</label>
            <button
              onClick={handleClear}
              className="xcalibr-text-xs xcalibr-text-gray-500 hover:xcalibr-text-gray-300"
            >
              Clear
            </button>
          </div>
          <div className="xcalibr-bg-[#1e1e1e] xcalibr-border xcalibr-border-[#333] xcalibr-rounded xcalibr-p-2">
            <code className="xcalibr-text-sm xcalibr-text-green-400 xcalibr-break-all">
              {generatedQuery}
            </code>
          </div>
          <div className="xcalibr-flex xcalibr-gap-2">
            <button
              onClick={handleCopy}
              className="xcalibr-flex-1 xcalibr-bg-[#333] xcalibr-text-white xcalibr-px-3 xcalibr-py-1 xcalibr-rounded xcalibr-text-sm hover:xcalibr-bg-[#444]"
            >
              {copied ? 'Copied!' : 'Copy'}
            </button>
            <button
              onClick={handleSearch}
              className="xcalibr-flex-1 xcalibr-bg-blue-600 xcalibr-text-white xcalibr-px-3 xcalibr-py-1 xcalibr-rounded xcalibr-text-sm hover:xcalibr-bg-blue-700"
            >
              Search
            </button>
          </div>
        </div>
      )}

      {/* History */}
      {history.length > 0 && (
        <div className="xcalibr-flex xcalibr-flex-col xcalibr-gap-1">
          <label className="xcalibr-text-xs xcalibr-text-gray-400">Recent Queries</label>
          <div className="xcalibr-flex xcalibr-flex-col xcalibr-gap-1 xcalibr-max-h-24 xcalibr-overflow-y-auto">
            {history.slice(0, 5).map((entry, i) => (
              <button
                key={i}
                onClick={() => handleHistorySelect(entry.query)}
                className="xcalibr-text-left xcalibr-bg-[#1e1e1e] xcalibr-border xcalibr-border-[#333] xcalibr-rounded xcalibr-px-2 xcalibr-py-1 xcalibr-text-xs xcalibr-text-gray-400 hover:xcalibr-border-[#555] xcalibr-truncate"
              >
                {entry.query}
              </button>
            ))}
          </div>
        </div>
      )}

      {!domain && (
        <div className="xcalibr-text-sm xcalibr-text-gray-400 xcalibr-text-center xcalibr-py-2">
          Enter a domain to generate Google dork queries
        </div>
      )}
    </div>
  );
};

export class GoogleDorkGeneratorTool {
  static Component = GoogleDorkGeneratorToolComponent;
}
