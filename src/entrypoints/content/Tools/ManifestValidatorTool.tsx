import React from 'react';

export type ManifestValidatorData = {
  input?: string;
  errors?: string[];
  warnings?: string[];
  valid?: boolean;
};

type Props = {
  data: ManifestValidatorData | undefined;
  onChange: (data: ManifestValidatorData) => void;
};

const MV3_REQUIRED_FIELDS = ['manifest_version', 'name', 'version'];
const MV3_DEPRECATED_FIELDS = ['background.scripts', 'background.page', 'browser_action', 'page_action'];

const validateManifest = (input: string): { errors: string[]; warnings: string[] } => {
  const errors: string[] = [];
  const warnings: string[] = [];

  try {
    const manifest = JSON.parse(input);

    // Check required fields
    for (const field of MV3_REQUIRED_FIELDS) {
      if (!(field in manifest)) {
        errors.push(`Missing required field: ${field}`);
      }
    }

    // Check manifest version
    if (manifest.manifest_version !== 3) {
      errors.push('manifest_version must be 3 for MV3');
    }

    // Check for deprecated fields
    for (const field of MV3_DEPRECATED_FIELDS) {
      const parts = field.split('.');
      let obj = manifest;
      let found = true;
      for (const part of parts) {
        if (obj && typeof obj === 'object' && part in obj) {
          obj = obj[part];
        } else {
          found = false;
          break;
        }
      }
      if (found) {
        errors.push(`Deprecated in MV3: ${field}`);
      }
    }

    // Check background
    if (manifest.background) {
      if (!manifest.background.service_worker && !manifest.background.scripts) {
        warnings.push('Background should use service_worker in MV3');
      }
    }

    // Check for persistent background
    if (manifest.background?.persistent === true) {
      errors.push('persistent: true is not allowed in MV3');
    }

    // Check permissions
    if (manifest.permissions) {
      const deprecatedPerms = ['unlimitedStorage', 'gcm'];
      for (const perm of deprecatedPerms) {
        if (manifest.permissions.includes(perm)) {
          warnings.push(`Permission '${perm}' may have different behavior in MV3`);
        }
      }
    }

    // Check web_accessible_resources format
    if (manifest.web_accessible_resources) {
      if (Array.isArray(manifest.web_accessible_resources) &&
          manifest.web_accessible_resources.length > 0 &&
          typeof manifest.web_accessible_resources[0] === 'string') {
        errors.push('web_accessible_resources must use object format in MV3');
      }
    }

    // Check content_security_policy format
    if (manifest.content_security_policy && typeof manifest.content_security_policy === 'string') {
      errors.push('content_security_policy must be an object in MV3');
    }

    // Check action
    if (!manifest.action && (manifest.browser_action || manifest.page_action)) {
      warnings.push('Use "action" instead of browser_action/page_action in MV3');
    }

    // Check icons
    if (!manifest.icons) {
      warnings.push('Icons are recommended for better user experience');
    }

  } catch {
    errors.push('Invalid JSON syntax');
  }

  return { errors, warnings };
};

const ManifestValidator: React.FC<Props> = ({ data, onChange }) => {
  const input = data?.input ?? '';
  const errors = data?.errors ?? [];
  const warnings = data?.warnings ?? [];
  const valid = data?.valid;

  const handleValidate = () => {
    const result = validateManifest(input);
    onChange({
      ...data,
      errors: result.errors,
      warnings: result.warnings,
      valid: result.errors.length === 0
    });
  };

  const loadSampleManifest = () => {
    const sample = {
      manifest_version: 3,
      name: 'My Extension',
      version: '1.0.0',
      description: 'A sample MV3 extension',
      action: {
        default_popup: 'popup.html',
        default_icon: {
          '16': 'icons/icon16.png',
          '48': 'icons/icon48.png',
          '128': 'icons/icon128.png'
        }
      },
      background: {
        service_worker: 'background.js'
      },
      permissions: ['storage', 'activeTab'],
      icons: {
        '16': 'icons/icon16.png',
        '48': 'icons/icon48.png',
        '128': 'icons/icon128.png'
      }
    };
    onChange({
      ...data,
      input: JSON.stringify(sample, null, 2),
      errors: [],
      warnings: [],
      valid: undefined
    });
  };

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <button
          onClick={loadSampleManifest}
          className="flex-1 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded text-xs"
        >
          Load Sample
        </button>
        <button
          onClick={handleValidate}
          className="flex-1 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs"
        >
          Validate
        </button>
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Paste manifest.json</label>
        <textarea
          value={input}
          onChange={(e) => onChange({ ...data, input: e.target.value, valid: undefined })}
          placeholder='{ "manifest_version": 3, ... }'
          rows={12}
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-xs resize-none"
        />
      </div>

      {valid !== undefined && (
        <div className={`p-3 rounded ${valid ? 'bg-green-900/30 border border-green-700' : 'bg-red-900/30 border border-red-700'}`}>
          <div className={`text-sm font-bold ${valid ? 'text-green-400' : 'text-red-400'}`}>
            {valid ? '✓ Valid MV3 Manifest' : '✗ Invalid Manifest'}
          </div>
        </div>
      )}

      {errors.length > 0 && (
        <div>
          <label className="block text-xs text-red-400 mb-1">Errors ({errors.length})</label>
          <div className="space-y-1">
            {errors.map((error, i) => (
              <div key={i} className="text-xs text-red-300 bg-red-900/20 rounded px-2 py-1">
                ✗ {error}
              </div>
            ))}
          </div>
        </div>
      )}

      {warnings.length > 0 && (
        <div>
          <label className="block text-xs text-yellow-400 mb-1">Warnings ({warnings.length})</label>
          <div className="space-y-1">
            {warnings.map((warning, i) => (
              <div key={i} className="text-xs text-yellow-300 bg-yellow-900/20 rounded px-2 py-1">
                ⚠ {warning}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export class ManifestValidatorTool {
  static Component = ManifestValidator;
}
