import React from 'react';
import { Shield, Radio, Github, Globe, Menu, X } from 'lucide-react';
import { CapabilitiesResponse } from '../types';

export type NavTab = 'scanner' | 'results' | 'how-it-works' | 'cli-guide' | 'settings';

interface NavbarProps {
  activeTab: NavTab;
  setActiveTab: (tab: NavTab) => void;
  capabilities: CapabilitiesResponse | null;
  resultCount?: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  capabilities,
  resultCount = 0,
}) => {
  const [mobileMenuOpen, setMobileMenuOpen] = React.useState(false);

  const isAgentOnline = Boolean(capabilities?.external_agent_configured);
  const isVercel = capabilities?.deployment === 'vercel';

  const navLinks: { id: NavTab; label: string; badge?: string }[] = [
    { id: 'scanner', label: 'Scanner' },
    { id: 'results', label: 'Results', badge: resultCount > 0 ? String(resultCount) : undefined },
    { id: 'how-it-works', label: 'How It Works' },
    { id: 'cli-guide', label: 'CLI Guide' },
    { id: 'settings', label: 'Settings & Connection' },
  ];

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800/80 bg-[#0f1523]/95 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6">
        <div className="flex items-center justify-between h-16 gap-4">
          {/* Brand & Subtitle */}
          <div className="flex items-center gap-3 shrink-0">
            <div className="w-9 h-9 rounded-lg bg-rose-950/60 border border-rose-500/30 flex items-center justify-center text-rose-500 shadow-sm">
              <Shield className="w-5 h-5 text-rose-500" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm sm:text-base font-bold text-white tracking-tight">
                  Network Discovery &amp; Security Inventory
                </span>
              </div>
              <p className="text-[11px] text-slate-400 hidden sm:block">
                Built by Isha Sonaria · Authorized network inventory &amp; port reconnaissance
              </p>
            </div>
          </div>

          {/* Desktop Navigation Links */}
          <nav className="hidden lg:flex items-center gap-1">
            {navLinks.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium rounded-lg transition-colors whitespace-nowrap ${
                    isActive
                      ? 'bg-rose-950/40 text-rose-400 border border-rose-500/30 font-semibold'
                      : 'text-slate-300 hover:text-white hover:bg-slate-800/60'
                  }`}
                >
                  <span>{item.label}</span>
                  {item.badge && (
                    <span className="ml-0.5 px-1.5 py-0.2 text-[10px] font-mono rounded-full bg-rose-900/60 text-rose-300 font-bold border border-rose-700/50">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>

          {/* Right Status Badge & Links */}
          <div className="flex items-center gap-3">
            {/* Deployment & Scanner Status */}
            <div
              className={`hidden sm:flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-medium border ${
                isAgentOnline
                  ? 'bg-emerald-950/40 text-emerald-400 border-emerald-800/60'
                  : 'bg-slate-900/60 text-slate-300 border-slate-800'
              }`}
              title={
                isAgentOnline
                  ? 'Connected to local Kali Linux agent (Layer 2 ARP enabled)'
                  : isVercel
                  ? 'Running in Vercel Serverless environment (Layer 3 TCP enabled)'
                  : 'Running on local server runtime'
              }
            >
              <span
                className={`w-2 h-2 rounded-full ${
                  isAgentOnline ? 'bg-emerald-500 animate-pulse' : 'bg-slate-500'
                }`}
              />
              <span className="font-sans text-[11px]">
                {isAgentOnline ? 'Agent Connected' : isVercel ? 'Cloud Serverless' : 'Serverless Ready'}
              </span>
            </div>

            {/* Author Profile Links */}
            <div className="flex items-center gap-1.5 text-slate-400 border-l border-slate-800 pl-3">
              <a
                href="https://github.com/ishasonaria568-prog"
                target="_blank"
                rel="noopener noreferrer"
                title="GitHub: ishasonaria568-prog"
                className="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-slate-800/60 rounded-md transition-colors"
              >
                <Github className="w-4 h-4" />
              </a>
              <a
                href="https://isha-sonaria-cybersecurity-portfoli.vercel.app/"
                target="_blank"
                rel="noopener noreferrer"
                title="Portfolio: Isha Sonaria"
                className="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-slate-800/60 rounded-md transition-colors"
              >
                <Globe className="w-4 h-4" />
              </a>
            </div>

            {/* Mobile Menu Button */}
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="lg:hidden p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-md"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>

        {/* Mobile Dropdown Navigation */}
        {mobileMenuOpen && (
          <div className="lg:hidden py-3 border-t border-slate-800 space-y-1">
            {navLinks.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => {
                    setActiveTab(item.id);
                    setMobileMenuOpen(false);
                  }}
                  className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md text-left ${
                    isActive
                      ? 'bg-rose-950/40 text-rose-400 font-semibold border border-rose-500/30'
                      : 'text-slate-300 hover:bg-slate-800/60'
                  }`}
                >
                  <span>{item.label}</span>
                  {item.badge && (
                    <span className="px-1.5 py-0.2 text-[10px] font-mono rounded-full bg-rose-900/60 text-rose-300 font-bold border border-rose-700/50">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        )}
      </div>
    </header>
  );
};
