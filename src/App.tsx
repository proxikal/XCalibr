import React, { useState, useMemo } from 'react';
import { Header } from '@/components/layout/Header';
import { TabNavigation } from '@/components/layout/TabNavigation';
import { Footer } from '@/components/layout/Footer';
import { ToolCard } from '@/components/ui/ToolCard';
import { SearchBar } from '@/components/ui/SearchBar';
import { Pagination } from '@/components/ui/Pagination';
import { CrashRecoveryNotification } from '@/components/CrashRecoveryNotification';
import { useActiveTab, useToolState, useUIState } from '@/hooks/useAppStore';
import { tools } from '@/data/tools';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useActiveTab();
  const { toolState, recordToolUsage, toggleFavorite } = useToolState();
  const { uiState, setCurrentPage } = useUIState();
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

  return (
    <div className="h-full w-full flex flex-col bg-dev-dark text-slate-300 antialiased selection:bg-dev-green selection:text-black">
      {/* Crash Recovery Notification */}
      <CrashRecoveryNotification />

      <Header />

      {/* Search Bar with Favorites Toggle */}
      <SearchBar />

      <TabNavigation activeTab={activeTab} onTabChange={setActiveTab} />

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

      <Footer />
    </div>
  );
};
