import React, { useMemo, useEffect } from 'react';
import { Header } from '@/components/layout/Header';
import { TabNavigation } from '@/components/layout/TabNavigation';
import { Footer } from '@/components/layout/Footer';
import { ToolCard } from '@/components/ui/ToolCard';
import { SearchBar } from '@/components/ui/SearchBar';
import { Pagination } from '@/components/ui/Pagination';
import { CrashRecoveryNotification } from '@/components/CrashRecoveryNotification';
import { ToolView } from '@/components/ToolView';
import { FeaturesTab } from '@/components/FeaturesTab';
import { useActiveTab, useToolState, useUIState, useNavigation } from '@/hooks/useAppStore';
import { tools } from '@/data/tools';
import type { TabCategory } from '@/types';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useActiveTab();
  const { toolState, recordToolUsage, toggleFavorite } = useToolState();
  const { uiState, setCurrentPage } = useUIState();
  const { activeView, openTool } = useNavigation();

  // Auto-switch tab when searching if no results in current tab
  useEffect(() => {
    if (!uiState.searchQuery) return;

    const query = uiState.searchQuery.toLowerCase();

    // Check if current tab has any matches
    const currentTabTools = tools.filter(
      (tool) =>
        tool.category === activeTab &&
        (tool.name.toLowerCase().includes(query) ||
          tool.description.toLowerCase().includes(query))
    );

    // If current tab has matches, don't switch
    if (currentTabTools.length > 0) return;

    // Find first tab with matches (priority: frontend -> backend -> other)
    const tabPriority: TabCategory[] = ['frontend', 'backend', 'other'];

    for (const tab of tabPriority) {
      const tabTools = tools.filter(
        (tool) =>
          tool.category === tab &&
          (tool.name.toLowerCase().includes(query) ||
            tool.description.toLowerCase().includes(query))
      );

      if (tabTools.length > 0) {
        console.log(`🔍 Auto-switching to ${tab} tab - found ${tabTools.length} matching tools`);
        setActiveTab(tab);
        break;
      }
    }
  }, [uiState.searchQuery, activeTab, setActiveTab]);

  const handleToolClick = (toolId: string, toolName: string) => {
    console.log(`Tool clicked: ${toolName}`);

    // Record tool usage in persistent store
    recordToolUsage(toolId);

    // Open tool view
    openTool(toolId);
  };

  const handleToggleFavorite = (e: React.MouseEvent, toolId: string) => {
    e.stopPropagation(); // Prevent tool click when clicking favorite
    toggleFavorite(toolId);
  };

  // Filter and paginate tools
  const { paginatedTools, totalPages, totalFilteredItems } = useMemo(() => {
    // Filter by category
    let filtered = tools.filter((tool) => tool.category === activeTab);

    // Filter by search query
    if (uiState.searchQuery) {
      const query = uiState.searchQuery.toLowerCase();
      filtered = filtered.filter(
        (tool) =>
          tool.name.toLowerCase().includes(query) ||
          tool.description.toLowerCase().includes(query)
      );
    }

    // Filter by favorites
    if (uiState.showFavoritesOnly) {
      filtered = filtered.filter((tool) =>
        toolState.favoriteTools.includes(tool.id)
      );
    }

    const totalItems = filtered.length;
    const totalPgs = Math.ceil(totalItems / uiState.itemsPerPage);

    // Paginate
    const startIndex = (uiState.currentPage - 1) * uiState.itemsPerPage;
    const endIndex = startIndex + uiState.itemsPerPage;
    const paginated = filtered.slice(startIndex, endIndex);

    return {
      paginatedTools: paginated,
      totalPages: totalPgs,
      totalFilteredItems: totalItems,
    };
  }, [activeTab, uiState, toolState.favoriteTools]);

  // Render tool view if a tool is active
  if (activeView === 'tool-detail') {
    return (
      <div className="h-full w-full flex flex-col bg-dev-dark text-slate-300 antialiased selection:bg-dev-green selection:text-black">
        <CrashRecoveryNotification />
        <Header />
        <ToolView />
        <Footer />
      </div>
    );
  }

  // Render tool list
  return (
    <div className="h-full w-full flex flex-col bg-dev-dark text-slate-300 antialiased selection:bg-dev-green selection:text-black">
      {/* Crash Recovery Notification */}
      <CrashRecoveryNotification />

      <Header />

      {/* Search Bar with Favorites Toggle */}
      <SearchBar />

      <TabNavigation activeTab={activeTab} onTabChange={setActiveTab} />

      {/* Render Features Tab or Tools */}
      {activeTab === 'features' ? (
        <FeaturesTab />
      ) : (
        <>
          <main className="flex-1 overflow-y-auto p-4 space-y-5 custom-scrollbar relative">
            {/* Background Gradient decoration */}
            <div className="fixed top-0 right-0 -mr-20 -mt-20 w-64 h-64 bg-dev-green/5 blur-3xl rounded-full pointer-events-none"></div>

            {/* Tool Cards */}
            <div className="space-y-3 relative z-0">
              {paginatedTools.length > 0 ? (
                paginatedTools.map((tool) => (
                  <ToolCard
                    key={tool.id}
                    tool={tool}
                    isFavorite={toolState.favoriteTools.includes(tool.id)}
                    onClick={() => handleToolClick(tool.id, tool.name)}
                    onToggleFavorite={(e) => handleToggleFavorite(e, tool.id)}
                  />
                ))
              ) : (
                <div className="text-center py-12">
                  <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-slate-800/50 border border-slate-700 mb-4">
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      fill="none"
                      viewBox="0 0 24 24"
                      strokeWidth="1.5"
                      stroke="currentColor"
                      className="w-8 h-8 text-slate-600"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z"
                      />
                    </svg>
                  </div>
                  <p className="text-slate-500 text-sm">
                    {uiState.showFavoritesOnly
                      ? 'No favorite tools yet. Click the star on a tool to add it to favorites.'
                      : 'No tools found matching your search.'}
                  </p>
                </div>
              )}
            </div>

          </main>

          {/* Pagination */}
          {paginatedTools.length > 0 && (
            <Pagination
              currentPage={uiState.currentPage}
              totalPages={totalPages}
              onPageChange={setCurrentPage}
              totalItems={totalFilteredItems}
              itemsPerPage={uiState.itemsPerPage}
            />
          )}
        </>
      )}

      <Footer />
    </div>
  );
};
