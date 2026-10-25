'use client';

import React from 'react';
import { ShieldCheck, User, AlertTriangle, ShieldAlert, EyeOff, ServerOff } from 'lucide-react';
import { ChatMessage } from '../lib/types';

interface ChatMessageItemProps {
  message: ChatMessage;
}

export const ChatMessageItem: React.FC<ChatMessageItemProps> = ({ message }) => {
  const isUser = message.role === 'user';
  const isBlocked = message.isBlocked;
  const piiSummary = message.piiSummary;

  // Distinguish genuine Security Blocks vs Technical Gateway Errors
  const isTechnicalError = isBlocked && (
    message.blockType === 'error' ||
    message.content.toLowerCase().includes('timeout') ||
    message.content.toLowerCase().includes('unreachable') ||
    message.content.toLowerCase().includes('did not respond')
  );

  return (
    <div
      className={`py-5 px-4 sm:px-6 transition-colors ${
        isUser
          ? 'bg-transparent'
          : isTechnicalError
          ? 'bg-amber-50/70 dark:bg-amber-950/20 border-y border-amber-200 dark:border-amber-900/30'
          : isBlocked
          ? 'bg-red-50/70 dark:bg-red-950/20 border-y border-red-200 dark:border-red-900/30'
          : 'bg-white dark:bg-slate-900/40 border-y border-slate-200/80 dark:border-slate-800/40 shadow-xs'
      }`}
    >
      <div className="max-w-4xl mx-auto flex items-start space-x-3 sm:space-x-4">
        {/* Avatar */}
        <div className="flex-shrink-0 mt-0.5">
          {isUser ? (
            <div className="w-8 h-8 rounded-xl bg-slate-200 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 flex items-center justify-center text-cyan-700 dark:text-cyan-400 font-bold text-xs shadow-xs">
              <User className="w-4 h-4 text-cyan-700 dark:text-cyan-400" />
            </div>
          ) : isTechnicalError ? (
            <div className="w-8 h-8 rounded-xl bg-amber-100 dark:bg-amber-500/20 border border-amber-300 dark:border-amber-500/40 flex items-center justify-center text-amber-600 dark:text-amber-400 shadow-xs">
              <ServerOff className="w-4.5 h-4.5" />
            </div>
          ) : isBlocked ? (
            <div className="w-8 h-8 rounded-xl bg-red-100 dark:bg-red-500/20 border border-red-300 dark:border-red-500/40 flex items-center justify-center text-red-600 dark:text-red-400 shadow-xs">
              <ShieldAlert className="w-4.5 h-4.5" />
            </div>
          ) : (
            <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 border border-cyan-400/30 flex items-center justify-center text-white shadow-md shadow-cyan-500/20">
              <ShieldCheck className="w-4.5 h-4.5" />
            </div>
          )}
        </div>

        {/* Message Content Container */}
        <div className="flex-1 min-w-0 space-y-2">
          {/* Header row: Name & Timestamp & Badges */}
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className="text-xs font-bold text-slate-900 dark:text-slate-100">
                {isUser ? 'You' : 'Zaalima Security Gateway'}
              </span>
              {!isUser && !isBlocked && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-50 dark:bg-cyan-500/10 text-cyan-700 dark:text-cyan-400 border border-cyan-200 dark:border-cyan-500/20">
                  {message.model || 'llama3.2:3b'}
                </span>
              )}
              {isTechnicalError && (
                <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full bg-amber-100 dark:bg-amber-500/20 text-amber-800 dark:text-amber-400 border border-amber-300 dark:border-amber-500/30 flex items-center gap-1">
                  <ServerOff className="w-3 h-3" /> GATEWAY ERROR
                </span>
              )}
              {isBlocked && !isTechnicalError && (
                <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full bg-red-100 dark:bg-red-500/20 text-red-700 dark:text-red-400 border border-red-300 dark:border-red-500/30 flex items-center gap-1">
                  <ShieldAlert className="w-3 h-3" /> SECURITY BLOCK
                </span>
              )}
            </div>

            <span className="text-[11px] text-slate-400 dark:text-slate-500 font-mono">
              {message.timestamp}
            </span>
          </div>

          {/* PII Detection Banner (if prompt contained PII) */}
          {piiSummary && piiSummary.pii_detected && (
            <div className="p-2.5 rounded-xl bg-emerald-50 dark:bg-emerald-500/10 border border-emerald-200 dark:border-emerald-500/20 text-xs text-emerald-900 dark:text-emerald-300 flex items-center justify-between shadow-xs">
              <div className="flex items-center space-x-2">
                <EyeOff className="w-4 h-4 text-emerald-600 dark:text-emerald-400 flex-shrink-0" />
                <span>
                  <strong className="font-semibold text-emerald-950 dark:text-emerald-200">PII Redacted:</strong> {piiSummary.count} entit(ies) stripped before LLM context ({piiSummary.entity_types.join(', ')})
                </span>
              </div>
              <span className="text-[10px] uppercase font-bold tracking-wider px-1.5 py-0.5 bg-emerald-200/80 dark:bg-emerald-500/20 rounded text-emerald-900 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-500/30">
                Presidio Safe
              </span>
            </div>
          )}

          {/* Message Text / Block Banner */}
          {isTechnicalError ? (
            <div className="p-4 rounded-2xl bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/50 text-amber-950 dark:text-amber-200 space-y-1">
              <p className="text-xs font-semibold text-amber-900 dark:text-amber-300">
                Gateway Timeout / Processing Error
              </p>
              <p className="text-[11px] text-amber-800 dark:text-amber-400/90 leading-relaxed">
                {message.content}
              </p>
            </div>
          ) : isBlocked ? (
            <div className="p-4 rounded-2xl bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800/50 text-red-950 dark:text-red-200 space-y-2">
              <div className="flex items-start space-x-2.5">
                <AlertTriangle className="w-5 h-5 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <p className="text-xs font-semibold text-red-900 dark:text-red-300">
                    {message.content}
                  </p>
                  <p className="text-[11px] text-red-700 dark:text-red-400/80 leading-relaxed">
                    This request was intercepted and blocked by the Zaalima Security Gateway protection layers.
                  </p>
                </div>
              </div>
            </div>
          ) : (
            <div className="text-xs sm:text-sm text-slate-800 dark:text-slate-200 leading-relaxed whitespace-pre-wrap font-sans break-words">
              {message.content}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
