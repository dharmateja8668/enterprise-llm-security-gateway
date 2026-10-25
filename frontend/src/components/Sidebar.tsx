'use client';

import React from 'react';
import {
  Plus,
  MessageSquare,
  Trash2,
  LogOut,
} from 'lucide-react';
import { ChatSession, GatewayAuth } from '../lib/types';

interface SidebarProps {
  sessions: ChatSession[];
  activeSessionId: string;
  auth: GatewayAuth;
  onSelectSession: (id: string) => void;
  onNewChat: () => void;
  onDeleteSession: (id: string) => void;
  onOpenAuthModal: () => void;
  onLogout: () => void;
  isMobileOpen: boolean;
  onCloseMobile: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  sessions,
  activeSessionId,
  auth,
  onSelectSession,
  onNewChat,
  onDeleteSession,
  onOpenAuthModal,
  onLogout,
  isMobileOpen,
  onCloseMobile,
}) => {
  const role = auth.user?.role || 'employee';
  const department = auth.user?.department || 'General';

  const roleLabel =
    role.toLowerCase() === 'admin'
      ? 'Administrator'
      : role.toLowerCase() === 'security_analyst'
      ? 'Security Analyst'
      : 'Employee';

  return (
    <>
      {/* Mobile backdrop */}
      {isMobileOpen && (
        <div
          onClick={onCloseMobile}
          className="fixed inset-0 bg-black/60 backdrop-blur-sm z-30 lg:hidden"
        />
      )}

      <aside
        className={`fixed lg:static inset-y-0 left-0 w-72 h-full bg-slate-100/90 dark:bg-slate-950/95 border-r border-slate-200 dark:border-slate-800/80 flex flex-col flex-shrink-0 z-40 overflow-hidden transition-all duration-300 ease-in-out ${
          isMobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        {/* Top: New Chat Button (Fixed flex-shrink-0) */}
        <div className="p-4 flex-shrink-0">
          <button
            onClick={() => {
              onNewChat();
              onCloseMobile();
            }}
            className="w-full flex items-center justify-center space-x-2 py-2.5 px-4 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium text-sm shadow-md shadow-cyan-600/20 transition-all group cursor-pointer"
          >
            <Plus className="w-4 h-4 group-hover:rotate-90 transition-transform duration-200" />
            <span>New Security Session</span>
          </button>
        </div>

        {/* Middle: Conversation Sessions List (Only scrollable area: flex-1 min-h-0 overflow-y-auto) */}
        <div className="flex-1 min-h-0 overflow-y-auto px-3 py-2 space-y-1">
          {(() => {
            const previousChats = sessions.filter(
              (s) => (s.messages && s.messages.length > 0) || (s.title && s.title !== 'New Security Session')
            );
            return (
              <>
                <div className="px-3 pb-1 text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider flex items-center justify-between sticky top-0 bg-slate-100/95 dark:bg-slate-950/95 py-1 z-10">
                  <span>Previous Chats</span>
                  <span className="text-[10px] text-cyan-700 dark:text-cyan-400 bg-cyan-100 dark:bg-cyan-500/10 px-1.5 py-0.5 rounded border border-cyan-300 dark:border-cyan-500/20 font-mono">
                    {previousChats.length}
                  </span>
                </div>

                {previousChats.length === 0 ? (
                  <div className="px-3 py-6 text-center text-xs text-slate-400 dark:text-slate-500 italic">
                    No previous threads yet.
                  </div>
                ) : (
                  previousChats.map((session) => {
                    const isActive = session.id === activeSessionId;
                    return (
                      <div
                        key={session.id}
                        onClick={() => {
                          onSelectSession(session.id);
                          onCloseMobile();
                        }}
                        className={`group flex items-center justify-between px-3 py-2.5 rounded-xl cursor-pointer text-xs transition-all ${
                          isActive
                            ? 'bg-white dark:bg-slate-800/90 text-cyan-800 dark:text-cyan-400 font-semibold border border-cyan-300 dark:border-cyan-500/20 shadow-xs'
                            : 'text-slate-600 dark:text-slate-400 hover:bg-slate-200/80 dark:hover:bg-slate-900 hover:text-slate-900 dark:hover:text-slate-200'
                        }`}
                      >
                        <div className="flex items-center space-x-2.5 min-w-0 pr-2">
                          <MessageSquare className={`w-3.5 h-3.5 flex-shrink-0 ${isActive ? 'text-cyan-600 dark:text-cyan-400' : 'text-slate-400 dark:text-slate-500'}`} />
                          <span className="truncate">{session.title || 'Security Chat'}</span>
                        </div>

                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onDeleteSession(session.id);
                          }}
                          className="opacity-0 group-hover:opacity-100 p-1 rounded hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-400 hover:text-red-600 dark:hover:text-red-400 transition-all cursor-pointer"
                          title="Delete thread"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    );
                  })
                )}
              </>
            );
          })()}
        </div>

        {/* Bottom: User Profile & Logout Section (Fixed flex-shrink-0 mt-auto) */}
        <div className="p-3 border-t border-slate-200 dark:border-slate-800/80 bg-slate-200/80 dark:bg-slate-950/90 space-y-2 text-xs flex-shrink-0 mt-auto transition-colors">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2 min-w-0">
              <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-cyan-600/20 to-blue-600/20 border border-cyan-500/30 flex items-center justify-center text-cyan-700 dark:text-cyan-400 font-bold text-xs flex-shrink-0">
                {auth.userId ? auth.userId.charAt(0).toUpperCase() : 'U'}
              </div>
              <div className="min-w-0">
                <p className="text-slate-900 dark:text-slate-100 font-semibold truncate text-xs">{auth.user?.username || auth.userId || 'User'}</p>
                <div className="flex items-center space-x-1.5 mt-0.5">
                  <span className={`text-[9px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded border ${
                    role.toLowerCase() === 'admin'
                      ? 'bg-blue-100 dark:bg-blue-500/20 text-blue-800 dark:text-blue-300 border-blue-300 dark:border-blue-500/30'
                      : role.toLowerCase() === 'security_analyst'
                      ? 'bg-purple-100 dark:bg-purple-500/20 text-purple-800 dark:text-purple-300 border-purple-300 dark:border-purple-500/30'
                      : 'bg-emerald-100 dark:bg-emerald-500/20 text-emerald-800 dark:text-emerald-300 border-emerald-300 dark:border-emerald-500/30'
                  }`}>
                    {roleLabel}
                  </span>
                  <span className="text-[10px] text-slate-500 dark:text-slate-400 truncate">
                    {department}
                  </span>
                </div>
              </div>
            </div>

            <button
              onClick={onLogout}
              className="flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg bg-red-50 dark:bg-red-500/10 hover:bg-red-100 dark:hover:bg-red-500/20 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-500/20 text-xs font-medium transition-all group shadow-xs flex-shrink-0 cursor-pointer"
              title="Sign Out of Zaalima Gateway"
            >
              <LogOut className="w-3.5 h-3.5 group-hover:-translate-x-0.5 transition-transform" />
              <span>Logout</span>
            </button>
          </div>
        </div>
      </aside>
    </>
  );
};
