'use client';

import React from 'react';
import { Sun, Moon } from 'lucide-react';
import { useTheme } from '../lib/ThemeContext';

interface ThemeToggleProps {
  compact?: boolean;
}

export const ThemeToggle: React.FC<ThemeToggleProps> = ({ compact = false }) => {
  const { theme, toggleTheme } = useTheme();
  const isDark = theme === 'dark';

  return (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
      title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-slate-200/90 dark:bg-slate-900/90 border border-slate-300 dark:border-slate-800 text-xs font-semibold text-slate-700 dark:text-slate-300 hover:text-slate-950 dark:hover:text-white transition-all shadow-xs cursor-pointer group"
    >
      {isDark ? (
        <>
          <Moon className="w-3.5 h-3.5 text-cyan-400 group-hover:rotate-12 transition-transform" />
          {!compact && <span className="text-[11px] tracking-wide font-medium">🌙 Dark</span>}
        </>
      ) : (
        <>
          <Sun className="w-3.5 h-3.5 text-amber-500 group-hover:rotate-45 transition-transform" />
          {!compact && <span className="text-[11px] tracking-wide font-medium">☀️ Light</span>}
        </>
      )}
    </button>
  );
};
