'use client';

import React from 'react';
import { ShieldCheck, LayoutDashboard } from 'lucide-react';
import { ThemeToggle } from './ThemeToggle';

interface HeaderProps {
  userRole?: string;
  userId?: string;
}

export const Header: React.FC<HeaderProps> = ({ userRole, userId }) => {
  const isAdmin = userRole?.toLowerCase() === 'admin' || userRole?.toLowerCase() === 'administrator';

  return (
    <header className="h-16 border-b border-slate-200 dark:border-slate-800/80 bg-white/90 dark:bg-slate-950/90 backdrop-blur-md px-4 sm:px-6 flex items-center justify-between z-20 sticky top-0 transition-colors">
      {/* Left section: Branding & Title */}
      <div className="flex items-center space-x-3">
        <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 text-white shadow-md shadow-cyan-500/20">
          <ShieldCheck className="w-6 h-6" />
          <div className="absolute -bottom-0.5 -right-0.5 w-3.5 h-3.5 bg-emerald-500 border-2 border-white dark:border-slate-950 rounded-full" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-base font-bold tracking-tight text-slate-900 dark:text-white flex items-center gap-1.5">
              <span>Zaalima</span>
              <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-cyan-50 dark:bg-cyan-500/10 text-cyan-700 dark:text-cyan-400 border border-cyan-200 dark:border-cyan-500/20">
                Gateway v1.0
              </span>
            </h1>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 hidden sm:block">
            Enterprise LLM & GenAI Security Gateway
          </p>
        </div>
      </div>

      {/* Right section: Theme Toggle & Admin-Only SOC Dashboard Link */}
      <div className="flex items-center space-x-3">
        <ThemeToggle />

        {isAdmin && (
          <a
            href={userId ? `http://127.0.0.1:8081/dashboard?user_id=${encodeURIComponent(userId)}` : "http://127.0.0.1:8081/dashboard"}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-blue-50 dark:bg-blue-600/20 border border-blue-200 dark:border-blue-500/30 text-blue-700 dark:text-blue-300 hover:bg-blue-100 dark:hover:bg-blue-600/30 transition-all text-xs font-medium group shadow-xs cursor-pointer"
            title="Open SOC Compliance Dashboard (Administrator Only)"
          >
            <LayoutDashboard className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 group-hover:scale-110 transition-transform" />
            <span>SOC Dashboard</span>
          </a>
        )}
      </div>
    </header>
  );
};
