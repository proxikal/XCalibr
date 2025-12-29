/**
 * Settings Modal Component
 * Modal with tab system for managing extension settings
 */

import React, { useState } from 'react';
import { useSettings } from '@/hooks/useAppStore';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

type SettingsTab = 'general' | 'appearance' | 'data';

export const SettingsModal: React.FC<SettingsModalProps> = ({ isOpen, onClose }) => {
  const [settings, updateSettings] = useSettings();
  const [activeTab, setActiveTab] = useState<SettingsTab>('general');
  const [localSettings, setLocalSettings] = useState(settings);

  if (!isOpen) return null;

  const handleSave = () => {
    updateSettings(localSettings);
    onClose();
  };

  const handleReset = () => {
    setLocalSettings(settings);
  };

  const handleExportSettings = () => {
    const dataStr = JSON.stringify(settings, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataStr);
    const exportFileDefaultName = `xcalibr-settings-${Date.now()}.json`;

    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
  };

  const handleImportSettings = () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = 'application/json';
    input.onchange = (e: Event) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = (event) => {
          try {
            const imported = JSON.parse(event.target?.result as string);
            setLocalSettings({ ...localSettings, ...imported });
          } catch (error) {
            alert('Failed to import settings. Invalid file format.');
          }
        };
        reader.readAsText(file);
      }
    };
    input.click();
  };

  const tabs: Array<{ id: SettingsTab; label: string }> = [
    { id: 'general', label: 'General' },
    { id: 'appearance', label: 'Appearance' },
    { id: 'data', label: 'Data' },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="bg-dev-dark border border-slate-700 rounded-lg shadow-2xl w-[400px] h-[600px] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-slate-800">
          <h2 className="text-lg font-bold text-white">Settings</h2>
          <button
            onClick={onClose}
            className="text-slate-500 hover:text-white transition-colors p-1 rounded hover:bg-slate-800"
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              fill="none"
              viewBox="0 0 24 24"
              strokeWidth="1.5"
              stroke="currentColor"
              className="w-5 h-5"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M6 18L18 6M6 6l12 12"
              />
            </svg>
          </button>
        </div>

        {/* Tab Navigation */}
        <nav className="flex px-4 pt-3 gap-4 text-sm font-medium border-b border-slate-800">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`relative pb-2 transition-colors ${
                activeTab === tab.id ? 'text-white' : 'text-slate-500 hover:text-slate-300'
              }`}
            >
              {tab.label}
              <span
                className={`absolute bottom-0 left-0 h-0.5 rounded-t-full transition-all ${
                  activeTab === tab.id
                    ? 'w-full bg-dev-green shadow-[0_0_10px_0_rgba(0,230,0,0.6)]'
                    : 'w-0 bg-slate-600'
                }`}
              />
            </button>
          ))}
        </nav>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar">
          {activeTab === 'general' && (
            <div className="space-y-4">
              <div>
                <label className="flex items-center justify-between p-3 bg-dev-card/30 border border-slate-700 rounded-lg hover:bg-slate-800/50 transition-colors cursor-pointer">
                  <div>
                    <span className="text-sm font-medium text-slate-200">Notifications</span>
                    <p className="text-xs text-slate-500 mt-1">
                      Enable browser notifications for events
                    </p>
                  </div>
                  <input
                    type="checkbox"
                    checked={localSettings.notifications}
                    onChange={(e) =>
                      setLocalSettings({ ...localSettings, notifications: e.target.checked })
                    }
                    className="w-5 h-5 rounded border-slate-600 bg-slate-800 text-dev-green focus:ring-dev-green focus:ring-offset-0"
                  />
                </label>
              </div>
            </div>
          )}

          {activeTab === 'appearance' && (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-200 mb-2">Theme</label>
                <div className="space-y-2">
                  <label className="flex items-center p-3 bg-dev-card/30 border border-slate-700 rounded-lg hover:bg-slate-800/50 transition-colors cursor-pointer">
                    <input
                      type="radio"
                      name="theme"
                      value="dark"
                      checked={localSettings.theme === 'dark'}
                      onChange={(e) =>
                        setLocalSettings({
                          ...localSettings,
                          theme: e.target.value as 'dark' | 'light',
                        })
                      }
                      className="w-4 h-4 text-dev-green focus:ring-dev-green focus:ring-offset-0"
                    />
                    <span className="ml-3 text-sm text-slate-200">Dark Mode</span>
                  </label>
                  <label className="flex items-center p-3 bg-dev-card/30 border border-slate-700 rounded-lg hover:bg-slate-800/50 transition-colors cursor-pointer opacity-50">
                    <input
                      type="radio"
                      name="theme"
                      value="light"
                      disabled
                      checked={localSettings.theme === 'light'}
                      className="w-4 h-4 text-dev-green focus:ring-dev-green focus:ring-offset-0"
                    />
                    <span className="ml-3 text-sm text-slate-200">
                      Light Mode <span className="text-xs text-slate-600">(Coming Soon)</span>
                    </span>
                  </label>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'data' && (
            <div className="space-y-4">
              <div className="bg-dev-card/30 border border-slate-700 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-slate-200 mb-2">Export / Import</h3>
                <p className="text-xs text-slate-500 mb-4">
                  Save your settings to a file or load from a backup
                </p>
                <div className="flex gap-2">
                  <button
                    onClick={handleExportSettings}
                    className="flex-1 bg-dev-card border border-slate-600 text-slate-300 hover:text-white hover:border-slate-500 py-2 px-3 rounded-md text-xs font-medium transition-colors"
                  >
                    Export Settings
                  </button>
                  <button
                    onClick={handleImportSettings}
                    className="flex-1 bg-dev-card border border-slate-600 text-slate-300 hover:text-white hover:border-slate-500 py-2 px-3 rounded-md text-xs font-medium transition-colors"
                  >
                    Import Settings
                  </button>
                </div>
              </div>

              <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-yellow-400 mb-2">Clear All Data</h3>
                <p className="text-xs text-slate-400 mb-3">
                  This will reset all settings, favorites, and tool history
                </p>
                <button
                  onClick={() => {
                    if (confirm('Are you sure? This cannot be undone.')) {
                      chrome.storage.local.clear(() => {
                        alert('All data cleared. Please reload the extension.');
                        window.close();
                      });
                    }
                  }}
                  className="w-full bg-red-500/20 border border-red-500/50 text-red-400 hover:bg-red-500/30 py-2 px-3 rounded-md text-xs font-medium transition-colors"
                >
                  Clear All Data
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex gap-2 p-4 border-t border-slate-800">
          <button
            onClick={handleReset}
            className="flex-1 bg-dev-card border border-slate-600 text-slate-300 hover:text-white hover:border-slate-500 py-2 rounded-md text-sm font-medium transition-colors"
          >
            Reset
          </button>
          <button
            onClick={handleSave}
            className="flex-1 bg-dev-green text-black hover:bg-[#00ff00] py-2 rounded-md text-sm font-bold shadow-[0_0_15px_rgba(0,230,0,0.3)] hover:shadow-[0_0_20px_rgba(0,230,0,0.5)] transition-all"
          >
            Save Changes
          </button>
        </div>
      </div>
    </div>
  );
};
