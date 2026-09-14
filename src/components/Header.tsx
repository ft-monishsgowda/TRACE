import React, { useState, useEffect } from 'react';
import {
  Code2,
  Search,
  LayoutDashboard,
  FileText,
  Database,
  Network,
} from 'lucide-react';

export type ActiveTab = 'investigate' | 'dashboard' | 'report' | 'database' | 'patterns' | 'prompt_spec';

interface HeaderProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  hasResult: boolean;
  dbCount: number;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  hasResult,
  dbCount,
}) => {
  const [scrollProgress, setScrollProgress] = useState(0);

  useEffect(() => {
    const handleScroll = () => {
      const totalScroll = document.documentElement.scrollHeight - window.innerHeight;
      if (totalScroll > 0) {
        const currentProgress = (window.scrollY / totalScroll) * 100;
        setScrollProgress(Math.min(100, Math.max(0, currentProgress)));
      } else {
        setScrollProgress(0);
      }
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    handleScroll();
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <>
      {/* Top Navbar */}
      <header className="fixed top-0 left-0 w-full h-14 bg-[#0e0e10]/95 backdrop-blur-md border-b border-[#232324] flex justify-center z-50">
        {/* Scroll Progress Bar */}
        <div
          className="absolute bottom-0 left-0 h-[1.5px] bg-aurora transition-all duration-150 ease-out pointer-events-none"
          style={{ width: `${scrollProgress}%`, opacity: scrollProgress > 1 ? 1 : 0 }}
        />
        <div className="w-full max-w-[1240px] px-3.5 sm:px-6 flex items-center justify-between h-full gap-2">
          {/* Logo Left */}
          <div className="flex items-center gap-2.5 shrink-0">
            <button
              onClick={() => window.location.reload()}
              title="Refresh application"
              className="flex items-center gap-2 font-mono text-sm font-semibold tracking-wider text-[#fafafa] hover:opacity-80 transition-all hover:scale-105 active:scale-95 cursor-pointer"
            >
              <span className="w-2 h-2 rounded-full bg-[#fafafa] animate-pulse" />
              <span>T.R.A.C.E</span>
            </button>
            <span className="hidden sm:inline-block text-[10px] font-mono text-[#a1a1aa] bg-[#181818] px-2 py-0.5 rounded border border-[#5c5c61]">
              DFIR SOC v2.4
            </span>
          </div>

          {/* Desktop Navigation Links */}
          <nav className="hidden md:flex items-center gap-1.5 py-1">
            <button
              onClick={() => setActiveTab('investigate')}
              className={`font-sans text-xs sm:text-[13px] font-medium px-3 py-1.5 rounded-full transition-colors whitespace-nowrap cursor-pointer ${
                activeTab === 'investigate'
                  ? 'bg-[#fafafa] text-[#000000] shadow-sm'
                  : 'text-[#a1a1aa] hover:text-[#fafafa] hover:bg-[#181818]'
              }`}
            >
              investigate
            </button>

            {hasResult && (
              <>
                <button
                  onClick={() => setActiveTab('dashboard')}
                  className={`font-sans text-xs sm:text-[13px] font-medium px-3 py-1.5 rounded-full transition-colors whitespace-nowrap cursor-pointer ${
                    activeTab === 'dashboard'
                      ? 'bg-[#fafafa] text-[#000000] shadow-sm'
                      : 'text-[#a1a1aa] hover:text-[#fafafa] hover:bg-[#181818]'
                  }`}
                >
                  dashboard
                </button>

                <button
                  onClick={() => setActiveTab('report')}
                  className={`font-sans text-xs sm:text-[13px] font-medium px-3 py-1.5 rounded-full transition-colors whitespace-nowrap cursor-pointer ${
                    activeTab === 'report'
                      ? 'bg-[#fafafa] text-[#000000] shadow-sm'
                      : 'text-[#a1a1aa] hover:text-[#fafafa] hover:bg-[#181818]'
                  }`}
                >
                  forensic report
                </button>
              </>
            )}

            <button
              onClick={() => setActiveTab('database')}
              className={`font-sans text-xs sm:text-[13px] font-medium px-3 py-1.5 rounded-full transition-colors whitespace-nowrap flex items-center gap-1.5 cursor-pointer ${
                activeTab === 'database'
                  ? 'bg-[#fafafa] text-[#000000] shadow-sm'
                  : 'text-[#a1a1aa] hover:text-[#fafafa] hover:bg-[#181818]'
              }`}
            >
              <span>database</span>
              {dbCount > 0 && (
                <span
                  className={`text-[10px] px-1.5 py-0.2 rounded-full font-mono ${
                    activeTab === 'database'
                      ? 'bg-[#000000] text-[#fafafa]'
                      : 'bg-[#181818] text-[#a1a1aa] border border-[#5c5c61]'
                  }`}
                >
                  {dbCount}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('patterns')}
              className={`font-sans text-xs sm:text-[13px] font-medium px-3 py-1.5 rounded-full transition-colors whitespace-nowrap cursor-pointer ${
                activeTab === 'patterns'
                  ? 'bg-[#fafafa] text-[#000000] shadow-sm'
                  : 'text-[#a1a1aa] hover:text-[#fafafa] hover:bg-[#181818]'
              }`}
            >
              pattern telemetry
            </button>
          </nav>

          {/* Right Action: Prompt Spec button & mobile current view pill */}
          <div className="flex items-center gap-1.5">
            {/* Mobile indicator of current active view */}
            <div className="md:hidden flex items-center gap-1 text-[11px] font-mono text-[#a1a1aa] bg-[#181818] px-2 py-1 rounded-full border border-[#5c5c61]">
              <span className="w-1.5 h-1.5 rounded-full bg-[#fafafa]" />
              <span className="capitalize">{activeTab.replace('_', ' ')}</span>
            </div>

            <button
              onClick={() => setActiveTab('prompt_spec')}
              title="View Gemini System Prompt & Pydantic Models"
              className={`font-mono text-xs px-2.5 py-1.5 rounded-full border transition-colors flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
                activeTab === 'prompt_spec'
                  ? 'bg-[#fafafa] text-[#000000] border-[#fafafa] font-semibold'
                  : 'border-[#5c5c61] text-[#a1a1aa] hover:text-[#fafafa] hover:border-[#fafafa]'
              }`}
            >
              <Code2 className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Prompt &amp; Spec</span>
            </button>
          </div>
        </div>
      </header>

      {/* Mobile & Portrait Bottom Navigation Bar */}
      <nav
        aria-label="Mobile Navigation"
        className="fixed bottom-0 left-0 right-0 h-16 bg-[#0e0e10]/95 backdrop-blur-lg border-t border-[#232324] flex items-center justify-around z-50 md:hidden px-2 shadow-2xl safe-area-pb"
      >
        <button
          onClick={() => setActiveTab('investigate')}
          className={`flex flex-col items-center justify-center gap-0.5 flex-1 py-1 transition-colors cursor-pointer ${
            activeTab === 'investigate' ? 'text-[#fafafa]' : 'text-[#a1a1aa] hover:text-[#fafafa]'
          }`}
        >
          <div className={`p-1 rounded-full ${activeTab === 'investigate' ? 'bg-[#232324]' : ''}`}>
            <Search className="w-4 h-4" />
          </div>
          <span className="text-[10px] font-sans font-medium">Analyze</span>
        </button>

        {hasResult && (
          <>
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`flex flex-col items-center justify-center gap-0.5 flex-1 py-1 transition-colors cursor-pointer ${
                activeTab === 'dashboard' ? 'text-[#fafafa]' : 'text-[#a1a1aa] hover:text-[#fafafa]'
              }`}
            >
              <div className={`p-1 rounded-full ${activeTab === 'dashboard' ? 'bg-[#232324]' : ''}`}>
                <LayoutDashboard className="w-4 h-4" />
              </div>
              <span className="text-[10px] font-sans font-medium">Dashboard</span>
            </button>

            <button
              onClick={() => setActiveTab('report')}
              className={`flex flex-col items-center justify-center gap-0.5 flex-1 py-1 transition-colors cursor-pointer ${
                activeTab === 'report' ? 'text-[#fafafa]' : 'text-[#a1a1aa] hover:text-[#fafafa]'
              }`}
            >
              <div className={`p-1 rounded-full ${activeTab === 'report' ? 'bg-[#232324]' : ''}`}>
                <FileText className="w-4 h-4" />
              </div>
              <span className="text-[10px] font-sans font-medium">Dossier</span>
            </button>
          </>
        )}

        <button
          onClick={() => setActiveTab('database')}
          className={`flex flex-col items-center justify-center gap-0.5 flex-1 py-1 relative transition-colors cursor-pointer ${
            activeTab === 'database' ? 'text-[#fafafa]' : 'text-[#a1a1aa] hover:text-[#fafafa]'
          }`}
        >
          <div className={`p-1 rounded-full relative ${activeTab === 'database' ? 'bg-[#232324]' : ''}`}>
            <Database className="w-4 h-4" />
            {dbCount > 0 && (
              <span className="absolute -top-1 -right-1 w-3.5 h-3.5 bg-[#fafafa] text-[#000000] text-[9px] font-mono font-bold rounded-full flex items-center justify-center">
                {dbCount > 9 ? '9+' : dbCount}
              </span>
            )}
          </div>
          <span className="text-[10px] font-sans font-medium">Database</span>
        </button>

        <button
          onClick={() => setActiveTab('patterns')}
          className={`flex flex-col items-center justify-center gap-0.5 flex-1 py-1 transition-colors cursor-pointer ${
            activeTab === 'patterns' ? 'text-[#fafafa]' : 'text-[#a1a1aa] hover:text-[#fafafa]'
          }`}
        >
          <div className={`p-1 rounded-full ${activeTab === 'patterns' ? 'bg-[#232324]' : ''}`}>
            <Network className="w-4 h-4" />
          </div>
          <span className="text-[10px] font-sans font-medium">Patterns</span>
        </button>
      </nav>
    </>
  );
};
