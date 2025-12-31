import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faSearch, faCopy, faKey, faServer, faDatabase, faCloud } from '@fortawesome/free-solid-svg-icons';

export type DefaultCredentialCheckerData = {
  selectedCategory?: string;
  search?: string;
};

type Credential = {
  vendor: string;
  product: string;
  username: string;
  password: string;
  port?: number;
  notes?: string;
};

type Props = {
  data: DefaultCredentialCheckerData | undefined;
  onChange: (data: DefaultCredentialCheckerData) => void;
};

const CREDENTIAL_DATABASE: Record<string, Credential[]> = {
  routers: [
    { vendor: 'Cisco', product: 'Router/Switch', username: 'admin', password: 'admin' },
    { vendor: 'Cisco', product: 'Router/Switch', username: 'cisco', password: 'cisco' },
    { vendor: 'Netgear', product: 'Router', username: 'admin', password: 'password' },
    { vendor: 'Netgear', product: 'Router', username: 'admin', password: '1234' },
    { vendor: 'Linksys', product: 'Router', username: 'admin', password: 'admin' },
    { vendor: 'TP-Link', product: 'Router', username: 'admin', password: 'admin' },
    { vendor: 'D-Link', product: 'Router', username: 'admin', password: '' },
    { vendor: 'D-Link', product: 'Router', username: 'admin', password: 'admin' },
    { vendor: 'ASUS', product: 'Router', username: 'admin', password: 'admin' },
    { vendor: 'Ubiquiti', product: 'UniFi', username: 'ubnt', password: 'ubnt' }
  ],
  databases: [
    { vendor: 'MySQL', product: 'Database', username: 'root', password: '', port: 3306 },
    { vendor: 'MySQL', product: 'Database', username: 'root', password: 'root', port: 3306 },
    { vendor: 'PostgreSQL', product: 'Database', username: 'postgres', password: 'postgres', port: 5432 },
    { vendor: 'MongoDB', product: 'Database', username: 'admin', password: 'admin', port: 27017 },
    { vendor: 'Redis', product: 'Database', username: '', password: '', port: 6379 },
    { vendor: 'Elasticsearch', product: 'Database', username: 'elastic', password: 'changeme', port: 9200 },
    { vendor: 'Oracle', product: 'Database', username: 'system', password: 'oracle', port: 1521 },
    { vendor: 'MSSQL', product: 'Database', username: 'sa', password: '', port: 1433 }
  ],
  cms: [
    { vendor: 'WordPress', product: 'CMS', username: 'admin', password: 'admin' },
    { vendor: 'Joomla', product: 'CMS', username: 'admin', password: 'admin' },
    { vendor: 'Drupal', product: 'CMS', username: 'admin', password: 'admin' },
    { vendor: 'Magento', product: 'CMS', username: 'admin', password: '123123' },
    { vendor: 'PrestaShop', product: 'CMS', username: 'admin@admin.com', password: 'admin' }
  ],
  servers: [
    { vendor: 'Apache Tomcat', product: 'Web Server', username: 'tomcat', password: 'tomcat', port: 8080 },
    { vendor: 'Apache Tomcat', product: 'Web Server', username: 'admin', password: 'admin', port: 8080 },
    { vendor: 'Jenkins', product: 'CI/CD', username: 'admin', password: 'admin', port: 8080 },
    { vendor: 'JBoss', product: 'App Server', username: 'admin', password: 'admin', port: 8080 },
    { vendor: 'GlassFish', product: 'App Server', username: 'admin', password: 'adminadmin', port: 4848 },
    { vendor: 'WebLogic', product: 'App Server', username: 'weblogic', password: 'weblogic', port: 7001 }
  ],
  cloud: [
    { vendor: 'Grafana', product: 'Monitoring', username: 'admin', password: 'admin', port: 3000 },
    { vendor: 'Kibana', product: 'Monitoring', username: 'elastic', password: 'changeme', port: 5601 },
    { vendor: 'Prometheus', product: 'Monitoring', username: '', password: '', port: 9090 },
    { vendor: 'RabbitMQ', product: 'Message Queue', username: 'guest', password: 'guest', port: 15672 },
    { vendor: 'MinIO', product: 'Object Storage', username: 'minioadmin', password: 'minioadmin', port: 9000 }
  ],
  iot: [
    { vendor: 'Hikvision', product: 'IP Camera', username: 'admin', password: '12345' },
    { vendor: 'Dahua', product: 'IP Camera', username: 'admin', password: 'admin' },
    { vendor: 'Axis', product: 'IP Camera', username: 'root', password: 'pass' },
    { vendor: 'Samsung', product: 'Smart TV', username: '', password: '0000' },
    { vendor: 'Raspberry Pi', product: 'SBC', username: 'pi', password: 'raspberry' }
  ]
};

const CATEGORY_ICONS: Record<string, typeof faServer> = {
  routers: faServer,
  databases: faDatabase,
  cms: faKey,
  servers: faServer,
  cloud: faCloud,
  iot: faServer
};

const CATEGORY_LABELS: Record<string, string> = {
  routers: 'Routers & Network',
  databases: 'Databases',
  cms: 'CMS Platforms',
  servers: 'Application Servers',
  cloud: 'Cloud & DevOps',
  iot: 'IoT Devices'
};

const DefaultCredentialChecker: React.FC<Props> = ({ data, onChange }) => {
  const selectedCategory = data?.selectedCategory ?? 'routers';
  const search = data?.search ?? '';
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const credentials = CREDENTIAL_DATABASE[selectedCategory] || [];

  const filteredCredentials = credentials.filter(cred => {
    if (!search) return true;
    const searchLower = search.toLowerCase();
    return (
      cred.vendor.toLowerCase().includes(searchLower) ||
      cred.product.toLowerCase().includes(searchLower) ||
      cred.username.toLowerCase().includes(searchLower)
    );
  });

  const handleCopy = (cred: Credential, index: number) => {
    const text = `${cred.vendor} ${cred.product}\nUsername: ${cred.username}\nPassword: ${cred.password}${cred.port ? `\nPort: ${cred.port}` : ''}`;
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const handleCopyCredential = (value: string, index: number) => {
    navigator.clipboard.writeText(value);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">Default Credentials</div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Reference database of common default credentials for various systems and devices.
      </div>

      <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
        <div className="text-[10px] text-slate-500 mb-1">Category</div>
        <div className="flex flex-wrap gap-1">
          {Object.keys(CREDENTIAL_DATABASE).map(category => (
            <button
              key={category}
              onClick={() => onChange({ ...data, selectedCategory: category })}
              className={`px-2 py-1 text-[10px] rounded flex items-center gap-1 transition-colors ${
                selectedCategory === category
                  ? 'bg-blue-600/20 border border-blue-500/30 text-blue-300'
                  : 'bg-slate-800 border border-slate-700 text-slate-400 hover:border-slate-500'
              }`}
            >
              <FontAwesomeIcon icon={CATEGORY_ICONS[category] || faServer} className="w-2.5 h-2.5" />
              {CATEGORY_LABELS[category]}
            </button>
          ))}
        </div>
      </div>

      <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
        <div className="text-[10px] text-slate-500 mb-1">Search</div>
        <div className="relative">
          <FontAwesomeIcon
            icon={faSearch}
            className="absolute left-2 top-1/2 -translate-y-1/2 text-slate-500 w-2.5 h-2.5"
          />
          <input
            type="text"
            value={search}
            onChange={(e) => onChange({ ...data, search: e.target.value })}
            placeholder="Filter by vendor, product..."
            className="w-full pl-7 pr-2 py-1 rounded bg-slate-800 text-slate-200 text-[11px] border border-slate-700 focus:outline-none focus:border-blue-500"
          />
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-2">
        Showing {filteredCredentials.length} of {credentials.length} credentials
      </div>

      <div className="flex-1 overflow-y-auto space-y-2 min-h-0">
        {filteredCredentials.map((cred, index) => (
          <div
            key={index}
            className="rounded border border-slate-700 bg-slate-800/50 p-2"
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-[11px] text-slate-200 font-medium">{cred.vendor} - {cred.product}</span>
              <button
                onClick={() => handleCopy(cred, index)}
                className="text-[9px] text-slate-500 hover:text-slate-300"
                title="Copy all"
              >
                <FontAwesomeIcon icon={faCopy} className="w-2.5 h-2.5" />
              </button>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="flex items-center gap-1 text-[10px]">
                <span className="text-slate-500">User:</span>
                <button
                  onClick={() => handleCopyCredential(cred.username, index + 1000)}
                  className="text-green-400 hover:text-green-300 font-mono"
                  title="Click to copy"
                >
                  {cred.username || '(empty)'}
                </button>
              </div>
              <div className="flex items-center gap-1 text-[10px]">
                <span className="text-slate-500">Pass:</span>
                <button
                  onClick={() => handleCopyCredential(cred.password, index + 2000)}
                  className="text-yellow-400 hover:text-yellow-300 font-mono"
                  title="Click to copy"
                >
                  {cred.password || '(empty)'}
                </button>
              </div>
            </div>
            {cred.port && (
              <div className="mt-1 text-[10px] text-slate-500">
                Default Port: <span className="text-slate-300">{cred.port}</span>
              </div>
            )}
            {copiedIndex === index && (
              <div className="text-green-400 text-[10px] mt-1">Copied!</div>
            )}
          </div>
        ))}
      </div>

      <div className="text-[10px] text-slate-500 border-t border-slate-700 pt-2 mt-3 space-y-0.5">
        <div><strong>Warning:</strong> This tool is for authorized security testing only.</div>
        <div>Always obtain proper authorization before testing credentials.</div>
      </div>
    </div>
  );
};

export class DefaultCredentialCheckerTool {
  static Component = DefaultCredentialChecker;
}
