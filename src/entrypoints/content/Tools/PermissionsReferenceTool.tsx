import React from 'react';

export type PermissionsReferenceData = {
  search?: string;
  selectedPermission?: string;
};

type PermissionInfo = {
  name: string;
  warning: boolean;
  description: string;
  api?: string;
};

const PERMISSIONS: PermissionInfo[] = [
  { name: 'activeTab', warning: false, description: 'Access to currently active tab when user invokes the extension', api: 'tabs' },
  { name: 'alarms', warning: false, description: 'Schedule code to run at specific times', api: 'chrome.alarms' },
  { name: 'background', warning: false, description: 'Keeps extension running in background (MV2)', api: 'background' },
  { name: 'bookmarks', warning: true, description: 'Read and modify bookmarks', api: 'chrome.bookmarks' },
  { name: 'browsingData', warning: true, description: 'Clear browsing data', api: 'chrome.browsingData' },
  { name: 'clipboardRead', warning: true, description: 'Read clipboard content', api: 'navigator.clipboard' },
  { name: 'clipboardWrite', warning: false, description: 'Write to clipboard', api: 'navigator.clipboard' },
  { name: 'contentSettings', warning: true, description: 'Change content settings', api: 'chrome.contentSettings' },
  { name: 'contextMenus', warning: false, description: 'Add items to context menu', api: 'chrome.contextMenus' },
  { name: 'cookies', warning: true, description: 'Read and modify cookies', api: 'chrome.cookies' },
  { name: 'debugger', warning: true, description: 'Attach to tabs for debugging', api: 'chrome.debugger' },
  { name: 'declarativeContent', warning: false, description: 'Take actions based on page content', api: 'chrome.declarativeContent' },
  { name: 'declarativeNetRequest', warning: true, description: 'Block/modify network requests', api: 'chrome.declarativeNetRequest' },
  { name: 'downloads', warning: true, description: 'Manage downloads', api: 'chrome.downloads' },
  { name: 'geolocation', warning: true, description: 'Access user location', api: 'navigator.geolocation' },
  { name: 'history', warning: true, description: 'Read and modify browsing history', api: 'chrome.history' },
  { name: 'identity', warning: false, description: 'OAuth2 authentication', api: 'chrome.identity' },
  { name: 'idle', warning: false, description: 'Detect when machine is idle', api: 'chrome.idle' },
  { name: 'management', warning: true, description: 'Manage other extensions', api: 'chrome.management' },
  { name: 'nativeMessaging', warning: true, description: 'Communicate with native apps', api: 'chrome.runtime.connectNative' },
  { name: 'notifications', warning: false, description: 'Show system notifications', api: 'chrome.notifications' },
  { name: 'pageCapture', warning: true, description: 'Save pages as MHTML', api: 'chrome.pageCapture' },
  { name: 'privacy', warning: true, description: 'Control privacy settings', api: 'chrome.privacy' },
  { name: 'proxy', warning: true, description: 'Manage proxy settings', api: 'chrome.proxy' },
  { name: 'scripting', warning: true, description: 'Inject scripts into pages', api: 'chrome.scripting' },
  { name: 'storage', warning: false, description: 'Store data locally', api: 'chrome.storage' },
  { name: 'system.cpu', warning: false, description: 'Query CPU info', api: 'chrome.system.cpu' },
  { name: 'system.memory', warning: false, description: 'Query memory info', api: 'chrome.system.memory' },
  { name: 'system.storage', warning: false, description: 'Query storage info', api: 'chrome.system.storage' },
  { name: 'tabCapture', warning: true, description: 'Capture tab content', api: 'chrome.tabCapture' },
  { name: 'tabGroups', warning: false, description: 'Manage tab groups', api: 'chrome.tabGroups' },
  { name: 'tabs', warning: true, description: 'Access tab URLs and titles', api: 'chrome.tabs' },
  { name: 'topSites', warning: true, description: 'Access most visited sites', api: 'chrome.topSites' },
  { name: 'tts', warning: false, description: 'Text-to-speech', api: 'chrome.tts' },
  { name: 'ttsEngine', warning: false, description: 'Implement TTS engine', api: 'chrome.ttsEngine' },
  { name: 'unlimitedStorage', warning: false, description: 'Unlimited local storage', api: 'storage' },
  { name: 'webNavigation', warning: true, description: 'Track navigation events', api: 'chrome.webNavigation' },
  { name: 'webRequest', warning: true, description: 'Observe network requests', api: 'chrome.webRequest' }
];

type Props = {
  data: PermissionsReferenceData | undefined;
  onChange: (data: PermissionsReferenceData) => void;
};

const PermissionsReference: React.FC<Props> = ({ data, onChange }) => {
  const search = data?.search ?? '';
  const selectedPermission = data?.selectedPermission ?? '';

  const filteredPermissions = PERMISSIONS.filter(p =>
    p.name.toLowerCase().includes(search.toLowerCase()) ||
    p.description.toLowerCase().includes(search.toLowerCase())
  );

  const selectedInfo = PERMISSIONS.find(p => p.name === selectedPermission);

  const copyPermission = (name: string) => {
    navigator.clipboard.writeText(`"${name}"`);
  };

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs text-gray-400 mb-1">Search permissions</label>
        <input
          type="text"
          value={search}
          onChange={(e) => onChange({ ...data, search: e.target.value })}
          placeholder="Type to filter..."
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
        />
      </div>

      <div className="text-xs text-gray-400 flex gap-4">
        <span>Total: {PERMISSIONS.length}</span>
        <span>Filtered: {filteredPermissions.length}</span>
      </div>

      <div className="max-h-60 overflow-y-auto space-y-1">
        {filteredPermissions.map((perm) => (
          <div
            key={perm.name}
            onClick={() => onChange({ ...data, selectedPermission: perm.name })}
            className={`p-2 rounded cursor-pointer text-sm ${
              selectedPermission === perm.name
                ? 'bg-blue-900/50 border border-blue-700'
                : 'bg-[#1a1a2e] border border-gray-700 hover:border-gray-600'
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="font-mono text-white">{perm.name}</span>
              <div className="flex items-center gap-2">
                {perm.warning && (
                  <span className="text-xs text-yellow-400" title="Shows warning to user">⚠</span>
                )}
                <button
                  onClick={(e) => { e.stopPropagation(); copyPermission(perm.name); }}
                  className="text-xs text-gray-400 hover:text-white"
                >
                  Copy
                </button>
              </div>
            </div>
            <div className="text-xs text-gray-400 mt-1">{perm.description}</div>
          </div>
        ))}
      </div>

      {selectedInfo && (
        <div className="bg-[#1a1a2e] border border-gray-700 rounded p-3">
          <div className="text-sm font-bold text-white mb-2">{selectedInfo.name}</div>
          <div className="text-xs text-gray-300 space-y-1">
            <p>{selectedInfo.description}</p>
            {selectedInfo.api && (
              <p className="font-mono text-blue-400">API: {selectedInfo.api}</p>
            )}
            {selectedInfo.warning && (
              <p className="text-yellow-400">⚠ Shows permission warning to user</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export class PermissionsReferenceTool {
  static Component = PermissionsReference;
}
