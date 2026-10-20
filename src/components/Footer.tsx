import React from 'react';
import { Shield, Github, Globe, ExternalLink } from 'lucide-react';

export const Footer: React.FC = () => {
  return (
    <footer className="w-full border-t border-slate-200/90 bg-white mt-16 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 flex flex-col sm:flex-row items-center justify-between gap-4">
        {/* Brand Lockup */}
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-blue-600" />
          <span className="text-xs font-semibold text-slate-800">
            Network Scanner — Built by Isha Sonaria
          </span>
          <span className="text-slate-300 hidden sm:inline">|</span>
          <span className="text-xs text-slate-500 hidden sm:inline">
            Defensive Network Discovery &amp; Inventory Tool
          </span>
        </div>

        {/* Links */}
        <div className="flex items-center gap-5 text-xs text-slate-600">
          <a
            href="https://github.com/ishasonaria568-prog"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 hover:text-blue-600 transition-colors"
          >
            <Github className="w-3.5 h-3.5" />
            <span>GitHub Profile</span>
            <ExternalLink className="w-3 h-3 text-slate-400" />
          </a>

          <a
            href="https://isha-sonaria-cybersecurity-portfoli.vercel.app/"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 hover:text-blue-600 transition-colors"
          >
            <Globe className="w-3.5 h-3.5" />
            <span>Portfolio</span>
            <ExternalLink className="w-3 h-3 text-slate-400" />
          </a>
        </div>
      </div>
    </footer>
  );
};
