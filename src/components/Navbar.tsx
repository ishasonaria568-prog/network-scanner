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
    <header className="sticky top-0 z-40 w-full border-b border-slate-200/90 bg-white/95 backdrop-blur-sm">
      <div className="max-w-7xl mx-auto px-4 sm:px-6">
        <div className="flex items-center justify-between h-16 gap-4">
          {/* Brand and Subtitle */}
          <div className="flex items-center gap-3 shrink-0">
            <div className="w-9 h-9 rounded-lg bg-blue-50 border border-blue-200/80 flex items-center justify-center text-blue-600 shadow-xs">
              <Shield className="w-5 h-5 text-blue-600" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-base font-bold text-slate-900 tracking-tight">
                  Network Scanner
                </span>
                <span className="text-xs text-slate-600 font-medium">
                  by Isha Sonaria
                </span>
              </div>
              <p className="text-xs text-slate-500 hidden sm:block">
                Discover and inspect devices on authorized networks
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
                  className={`flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                    isActive
                      ? 'bg-blue-50 text-blue-700 font-semibold'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100/70'
                  }`}
                >
                  <span>{item.label}</span>
                  {item.badge && (
                    <span className="ml-0.5 px-1.5 py-0.2 text-[10px] font-mono rounded-full bg-blue-100 text-blue-700 font-bold">
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
                  ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                  : 'bg-slate-100 text-slate-700 border-slate-200'
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
                  isAgentOnline ? 'bg-emerald-500' : 'bg-slate-400'
                }`}
              />
              <span className="font-sans text-[11px]">
                {isAgentOnline ? 'Agent Connected' : isVercel ? 'Cloud Serverless' : 'Serverless Ready'}
              </span>
            </div>

            {/* Author Profile Links */}
            <div className="flex items-center gap-1.5 text-slate-500 border-l border-slate-200 pl-3">
              <a
                href="https://github.com/ishasonaria568-prog"
                target="_blank"
                rel="noopener noreferrer"
                title="GitHub: ishasonaria568-prog"
                className="p-1.5 text-slate-500 hover:text-slate-900 hover:bg-slate-100 rounded-md transition-colors"
              >
                <Github className="w-4 h-4" />
              </a>
              <a
                href="https://isha-sonaria-cybersecurity-portfoli.vercel.app/"
                target="_blank"
                rel="noopener noreferrer"
                title="Portfolio: Isha Sonaria"
                className="p-1.5 text-slate-500 hover:text-slate-900 hover:bg-slate-100 rounded-md transition-colors"
              >
                <Globe className="w-4 h-4" />
              </a>
            </div>

            {/* Mobile Menu Button */}
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="lg:hidden p-1.5 text-slate-600 hover:text-slate-900 hover:bg-slate-100 rounded-md"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>

        {/* Mobile Dropdown Navigation */}
        {mobileMenuOpen && (
          <div className="lg:hidden py-3 border-t border-slate-200 space-y-1">
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
                      ? 'bg-blue-50 text-blue-700 font-semibold'
                      : 'text-slate-600 hover:bg-slate-100'
                  }`}
                >
                  <span>{item.label}</span>
                  {item.badge && (
                    <span className="px-1.5 py-0.2 text-[10px] font-mono rounded-full bg-blue-100 text-blue-700">
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
