import React, { useState } from 'react';
import { Header } from '@/components/layout/Header';
import { TabNavigation } from '@/components/layout/TabNavigation';
import { Footer } from '@/components/layout/Footer';
import { ToolCard } from '@/components/ui/ToolCard';
import { CrashRecoveryNotification } from '@/components/CrashRecoveryNotification';
import { useActiveTab, useToolState } from '@/hooks/useAppStore';
import { tools } from '@/data/tools';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useActiveTab();
  const { recordToolUsage } = useToolState();
  const [notification, setNotification] = useState<string | null>(null);

  const handleToolClick = (toolId: string, toolName: string) => {
    console.log(`Tool clicked: ${toolName}`);

    // Record tool usage in persistent store
    recordToolUsage(toolId);

    // Show notification
    setNotification(`${toolName} coming soon!`);

    // Hide notification after 2 seconds
    setTimeout(() => {
      setNotification(null);
    }, 2000);
  };

  const filteredTools = tools.filter((tool) => tool.category === activeTab);

  return (
    <div className="h-full w-full flex flex-col bg-dev-dark text-slate-300 antialiased selection:bg-dev-green selection:text-black">
      {/* Crash Recovery Notification */}
      <CrashRecoveryNotification />

      <Header />
      <TabNavigation activeTab={activeTab} onTabChange={setActiveTab} />

      <main className="flex-1 overflow-y-auto p-4 space-y-5 custom-scrollbar relative">
        {/* Background Gradient decoration */}
        <div className="fixed top-0 right-0 -mr-20 -mt-20 w-64 h-64 bg-dev-green/5 blur-3xl rounded-full pointer-events-none"></div>

        {/* Tool Cards */}
        <div className="space-y-3 relative z-0">
          {filteredTools.map((tool) => (
            <ToolCard
              key={tool.id}
              tool={tool}
              onClick={() => handleToolClick(tool.id, tool.name)}
            />
          ))}
        </div>

        {/* Notification */}
        {notification && (
          <div className="fixed top-20 left-1/2 transform -translate-x-1/2 bg-dev-card border border-dev-green/40 text-white px-4 py-2 rounded-lg shadow-lg z-50 text-sm animate-fade-in">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 bg-dev-green rounded-full animate-pulse"></span>
              <span>
                <strong>{notification.split(' ')[0]}</strong> {notification.split(' ').slice(1).join(' ')}
              </span>
            </div>
          </div>
        )}
      </main>

      <Footer />
    </div>
  );
};
