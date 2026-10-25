'use client';

import React, { useState, useEffect } from 'react';
import { Header } from '../components/Header';
import { Sidebar } from '../components/Sidebar';
import { ChatMessageItem } from '../components/ChatMessageItem';
import { ChatInput } from '../components/ChatInput';
import { AuthModal } from '../components/AuthModal';
import { LoginPage } from '../components/LoginPage';
import { ChatSession, ChatMessage, GatewayAuth } from '../lib/types';
import {
  sendPromptToGateway,
  fetchUserChats,
  createUserChat,
  deleteUserChat,
  logoutGateway,
  checkGatewayHealth,
} from '../lib/api';
import {
  ShieldCheck,
  Menu,
  EyeOff,
  ShieldAlert,
  Bot,
  Zap,
  LayoutDashboard,
  Terminal,
  Code2,
  Lock,
} from 'lucide-react';

const SESSION_STORAGE_AUTH_KEY = 'zaalima_auth_config_v1';

export default function ChatbotPage() {
  const [auth, setAuth] = useState<GatewayAuth | null>(null);
  const [isAuthLoaded, setIsAuthLoaded] = useState<boolean>(false);
  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isHealthy, setIsHealthy] = useState<boolean>(true);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState<boolean>(false);
  const [isMobileSidebarOpen, setIsMobileSidebarOpen] = useState<boolean>(false);

  // 1. Load initial Auth settings from sessionStorage on mount
  useEffect(() => {
    try {
      const savedAuth = sessionStorage.getItem(SESSION_STORAGE_AUTH_KEY);
      if (savedAuth) {
        setAuth(JSON.parse(savedAuth));
      }
    } catch {
      setAuth(null);
    } finally {
      setIsAuthLoaded(true);
    }
  }, []);

  // 2. Fetch User-Isolated Chats whenever authenticated user changes
  useEffect(() => {
    if (!auth || !auth.userId) {
      setSessions([]);
      setActiveSessionId('');
      return;
    }

    const loadChatsForUser = async () => {
      // User-specific localStorage fallback + backend source of truth
      const userStorageKey = `zaalima_user_chats_${auth.userId}`;
      let cachedUserChats: ChatSession[] = [];
      try {
        const saved = localStorage.getItem(userStorageKey);
        if (saved) cachedUserChats = JSON.parse(saved);
      } catch {}

      // Fetch from Backend GET /chats
      const backendChats = await fetchUserChats(auth.apiKey, auth.userId, auth.apiUrl);

      if (backendChats && backendChats.length > 0) {
        setSessions(backendChats);
        setActiveSessionId(''); // ALWAYS start on Welcome Screen after login
        try {
          localStorage.setItem(userStorageKey, JSON.stringify(backendChats));
        } catch {}
      } else if (cachedUserChats.length > 0) {
        setSessions(cachedUserChats);
        setActiveSessionId(''); // ALWAYS start on Welcome Screen after login
      } else {
        setSessions([]);
        setActiveSessionId('');
      }
    };

    loadChatsForUser();
  }, [auth?.userId, auth?.apiKey, auth?.apiUrl]);

  // Save sessions to user-isolated localStorage key on update
  useEffect(() => {
    if (auth && auth.userId && sessions.length > 0) {
      try {
        const userStorageKey = `zaalima_user_chats_${auth.userId}`;
        localStorage.setItem(userStorageKey, JSON.stringify(sessions));
      } catch {}
    }
  }, [sessions, auth?.userId]);

  // Periodic gateway health check
  useEffect(() => {
    if (!auth) return;
    const doHealthCheck = async () => {
      const result = await checkGatewayHealth(auth.apiUrl);
      setIsHealthy(result.healthy);
    };

    doHealthCheck();
    const interval = setInterval(doHealthCheck, 20000);
    return () => clearInterval(interval);
  }, [auth?.apiUrl]);

  const handleLoginSuccess = (newAuth: GatewayAuth) => {
    // Clear old user's memory state before applying new user
    setSessions([]);
    setActiveSessionId(''); // Start on Welcome Screen for new login
    setAuth(newAuth);
    try {
      sessionStorage.setItem(SESSION_STORAGE_AUTH_KEY, JSON.stringify(newAuth));
    } catch {}
  };

  const handleLogout = async () => {
    if (auth) {
      await logoutGateway(auth.apiKey, auth.apiUrl);
    }
    // Clear user memory state completely
    setSessions([]);
    setActiveSessionId('');
    setAuth(null);
    try {
      sessionStorage.removeItem(SESSION_STORAGE_AUTH_KEY);
      localStorage.removeItem('zaalima_auth_config_v1'); // clear legacy localStorage key
    } catch {}
  };

  const saveAuthSettings = (newAuth: GatewayAuth) => {
    setAuth(newAuth);
    try {
      sessionStorage.setItem(SESSION_STORAGE_AUTH_KEY, JSON.stringify(newAuth));
    } catch {}
  };

  const createNewSession = async (): Promise<string> => {
    // Simply reset view to Welcome Screen without deleting previous chats
    setActiveSessionId('');
    return '';
  };

  const deleteSession = async (id: string) => {
    if (auth && auth.userId) {
      await deleteUserChat(id, auth.apiKey, auth.userId, auth.apiUrl);
    }

    setSessions((prev) => {
      const filtered = prev.filter((s) => s.id !== id);
      if (activeSessionId === id && filtered.length > 0) {
        setActiveSessionId(filtered[0].id);
      } else if (filtered.length === 0) {
        setActiveSessionId('');
      }
      return filtered;
    });
  };

  const activeSession = sessions.find((s) => s.id === activeSessionId);

  const handleSendMessage = async (userPrompt: string) => {
    if (!auth) return;

    let currentSessionId = activeSessionId;
    if (!currentSessionId || !sessions.some((s) => s.id === currentSessionId)) {
      const initialTitle = userPrompt.slice(0, 32) + (userPrompt.length > 32 ? '...' : '');
      const backendCreated = await createUserChat(initialTitle, auth.apiKey, auth.userId, auth.apiUrl);
      const newSessionId = backendCreated ? backendCreated.id : `session_${Date.now()}`;
      const newSession: ChatSession = {
        id: newSessionId,
        title: initialTitle,
        createdAt: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        messages: [],
      };
      currentSessionId = newSessionId;
      setSessions((prev) => [newSession, ...prev]);
      setActiveSessionId(newSessionId);
    }

    const timestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    const userMessage: ChatMessage = {
      id: `msg_user_${Date.now()}`,
      role: 'user',
      content: userPrompt,
      timestamp,
    };

    // Append user message immediately
    setSessions((prev) =>
      prev.map((session) => {
        if (session.id === currentSessionId) {
          const isFirstMessage = session.messages.length === 0;
          const updatedTitle = isFirstMessage
            ? userPrompt.slice(0, 32) + (userPrompt.length > 32 ? '...' : '')
            : session.title;

          return {
            ...session,
            title: updatedTitle,
            messages: [...session.messages, userMessage],
          };
        }
        return session;
      })
    );

    setIsLoading(true);

    // Call Zaalima FastAPI Gateway `/chat` with user_id and chat_id
    const apiResult = await sendPromptToGateway(
      userPrompt,
      auth.apiKey,
      auth.userId,
      currentSessionId,
      auth.apiUrl
    );

    setIsLoading(false);
    const respTimestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    let assistantMessage: ChatMessage;

    if (apiResult.success) {
      assistantMessage = {
        id: `msg_ai_${Date.now()}`,
        role: 'assistant',
        content: apiResult.response,
        timestamp: respTimestamp,
        model: apiResult.model,
        piiSummary: apiResult.pii_summary,
      };
    } else {
      assistantMessage = {
        id: `msg_ai_${Date.now()}`,
        role: 'assistant',
        content: apiResult.message,
        timestamp: respTimestamp,
        isBlocked: true,
        blockType: apiResult.blockType,
      };
    }

    // Append AI response or block message to session
    setSessions((prev) =>
      prev.map((session) => {
        if (session.id === currentSessionId) {
          return {
            ...session,
            messages: [...session.messages, assistantMessage],
          };
        }
        return session;
      })
    );
  };

  if (!isAuthLoaded) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-slate-950 flex items-center justify-center text-cyan-600 dark:text-cyan-400 font-sans text-xs">
        Initializing Zaalima Security Gateway...
      </div>
    );
  }

  // If unauthenticated, show Login Page
  if (!auth || !auth.userId) {
    return <LoginPage onLoginSuccess={handleLoginSuccess} />;
  }

  const userRole = auth.user?.role || 'employee';
  const roleLower = userRole.toLowerCase();
  const hasSocAccess = ['admin', 'administrator', 'soc_analyst', 'security_analyst', 'manager'].includes(roleLower);

  return (
    <div className="h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200 overflow-hidden transition-colors">
      {/* Header - Conditionally shows SOC Dashboard button for authorized roles */}
      <Header userRole={userRole} userId={auth.userId} />

      <div className="flex-1 flex min-h-0 overflow-hidden">
        {/* Mobile menu trigger */}
        <div className="lg:hidden fixed bottom-20 right-4 z-30">
          <button
            onClick={() => setIsMobileSidebarOpen(true)}
            className="p-3 rounded-full bg-cyan-600 text-white shadow-lg shadow-cyan-600/30 hover:bg-cyan-500 transition-all cursor-pointer"
          >
            <Menu className="w-5 h-5" />
          </button>
        </div>

        {/* Sidebar */}
        <Sidebar
          sessions={sessions}
          activeSessionId={activeSessionId}
          auth={auth}
          onSelectSession={setActiveSessionId}
          onNewChat={createNewSession}
          onDeleteSession={deleteSession}
          onOpenAuthModal={() => setIsAuthModalOpen(true)}
          onLogout={handleLogout}
          isMobileOpen={isMobileSidebarOpen}
          onCloseMobile={() => setIsMobileSidebarOpen(false)}
        />

        {/* Main Content Area */}
        <main className="flex-1 flex flex-col bg-slate-50/60 dark:bg-slate-950/60 overflow-hidden relative transition-colors">
          {/* Messages or Empty State */}
          <div className="flex-1 overflow-y-auto space-y-0 pb-6">
            {!activeSession || activeSession.messages.length === 0 ? (
              /* Reference-Inspired Empty State Welcome Screen */
              <div className="max-w-3xl mx-auto px-4 py-12 sm:py-20 text-center space-y-8 animate-fade-in">
                {/* Reference Headline & Subtitle */}
                <div className="space-y-3">
                  <h1 className="text-3xl sm:text-5xl font-extrabold text-slate-900 dark:text-white tracking-tight font-sans">
                    How can I help today?
                  </h1>
                  <p className="text-xs sm:text-sm text-slate-500 dark:text-slate-400 max-w-xl mx-auto leading-relaxed">
                    Ask anything or pick a starting point. All prompts are protected by Zaalima Security Gateway.
                  </p>
                </div>

                {/* Reference-Inspired 4 Suggestion Cards Grid */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 text-left max-w-2xl mx-auto">
                  {/* Card 1: Explain cybersecurity */}
                  <div
                    onClick={() =>
                      handleSendMessage(
                        "Explain key cybersecurity principles for deploying LLMs securely in enterprise environments."
                      )
                    }
                    className="p-4 rounded-2xl bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 hover:border-cyan-500/50 hover:bg-slate-50 dark:hover:bg-slate-800/80 cursor-pointer transition-all shadow-xs hover:shadow-md group"
                  >
                    <div className="flex items-center space-x-3">
                      <div className="p-2.5 rounded-xl bg-cyan-50 dark:bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 group-hover:scale-105 transition-transform flex-shrink-0">
                        <Lock className="w-5 h-5" />
                      </div>
                      <div>
                        <h3 className="text-xs font-bold text-slate-900 dark:text-white">
                          Explain cybersecurity
                        </h3>
                        <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                          Learn LLM security architecture
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* Card 2: Analyze a security log */}
                  <div
                    onClick={() =>
                      handleSendMessage(
                        "Analyze this security log: 'POST /v1/chat 403 Forbidden - Prompt injection detected from IP 192.168.1.105'"
                      )
                    }
                    className="p-4 rounded-2xl bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 hover:border-blue-500/50 hover:bg-slate-50 dark:hover:bg-slate-800/80 cursor-pointer transition-all shadow-xs hover:shadow-md group"
                  >
                    <div className="flex items-center space-x-3">
                      <div className="p-2.5 rounded-xl bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400 group-hover:scale-105 transition-transform flex-shrink-0">
                        <ShieldAlert className="w-5 h-5" />
                      </div>
                      <div>
                        <h3 className="text-xs font-bold text-slate-900 dark:text-white">
                          Analyze a security log
                        </h3>
                        <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                          Inspect threat alerts & status
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* Card 3: Explain an Nmap result */}
                  <div
                    onClick={() =>
                      handleSendMessage(
                        "Explain this Nmap scan output: 'PORT 80/tcp OPEN http, PORT 443/tcp OPEN ssl/https, PORT 8081/tcp OPEN unknown'"
                      )
                    }
                    className="p-4 rounded-2xl bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 hover:border-purple-500/50 hover:bg-slate-50 dark:hover:bg-slate-800/80 cursor-pointer transition-all shadow-xs hover:shadow-md group"
                  >
                    <div className="flex items-center space-x-3">
                      <div className="p-2.5 rounded-xl bg-purple-50 dark:bg-purple-500/10 text-purple-600 dark:text-purple-400 group-hover:scale-105 transition-transform flex-shrink-0">
                        <Terminal className="w-5 h-5" />
                      </div>
                      <div>
                        <h3 className="text-xs font-bold text-slate-900 dark:text-white">
                          Explain an Nmap result
                        </h3>
                        <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                          Decode network port scans
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* Card 4: Help with Python */}
                  <div
                    onClick={() =>
                      handleSendMessage(
                        "Write a secure Python script to sanitize prompt inputs and validate @zaalima.in email addresses."
                      )
                    }
                    className="p-4 rounded-2xl bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 hover:border-emerald-500/50 hover:bg-slate-50 dark:hover:bg-slate-800/80 cursor-pointer transition-all shadow-xs hover:shadow-md group"
                  >
                    <div className="flex items-center space-x-3">
                      <div className="p-2.5 rounded-xl bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 group-hover:scale-105 transition-transform flex-shrink-0">
                        <Code2 className="w-5 h-5" />
                      </div>
                      <div>
                        <h3 className="text-xs font-bold text-slate-900 dark:text-white">
                          Help with Python
                        </h3>
                        <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                          Build secure automation code
                        </p>
                      </div>
                    </div>
                  </div>
                </div>

                {/* User Status Badge */}
                <div className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-full bg-slate-200/80 dark:bg-slate-900 border border-slate-300 dark:border-slate-800 text-slate-700 dark:text-slate-300 text-xs font-medium">
                  <ShieldCheck className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
                  <span>Authenticated Workspace — User: {auth.userId} | Role: {userRole}</span>
                </div>

                {/* Dashboard Banner for Authorized Roles */}
                {hasSocAccess && (
                  <div className="max-w-2xl mx-auto p-4 rounded-2xl bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-950/40 dark:to-slate-900/60 border border-blue-200 dark:border-blue-800/40 flex flex-col sm:flex-row items-center justify-between gap-4 text-left shadow-xs">
                    <div className="flex items-center space-x-3">
                      <div className="p-2.5 rounded-xl bg-blue-100 dark:bg-blue-500/20 text-blue-700 dark:text-blue-400">
                        <LayoutDashboard className="w-5 h-5" />
                      </div>
                      <div>
                        <h4 className="text-xs font-bold text-slate-900 dark:text-white">
                          SOC Security & Compliance Dashboard
                        </h4>
                        <p className="text-[11px] text-slate-500 dark:text-slate-400">
                          View real-time security events, blocked prompts, and audit logs ({userRole.toUpperCase()} Privilege).
                        </p>
                      </div>
                    </div>
                    <a
                      href={`http://127.0.0.1:8081/dashboard?user_id=${encodeURIComponent(auth.userId)}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-md transition-all flex items-center gap-1.5 flex-shrink-0 cursor-pointer"
                    >
                      Launch Dashboard
                    </a>
                  </div>
                )}
              </div>
            ) : (
              activeSession.messages.map((message) => (
                <ChatMessageItem key={message.id} message={message} />
              ))
            )}

            {/* Loading Indicator */}
            {isLoading && (
              <div className="py-5 px-4 sm:px-6 bg-slate-100/80 dark:bg-slate-900/40 border-y border-slate-200 dark:border-slate-800/40">
                <div className="max-w-4xl mx-auto flex items-center space-x-3">
                  <div className="w-8 h-8 rounded-xl bg-cyan-100 dark:bg-cyan-500/20 border border-cyan-300 dark:border-cyan-500/30 flex items-center justify-center">
                    <Bot className="w-4 h-4 text-cyan-600 dark:text-cyan-400 animate-pulse" />
                  </div>
                  <div className="flex items-center space-x-2 text-xs text-cyan-800 dark:text-cyan-400 font-medium">
                    <span className="w-2 h-2 rounded-full bg-cyan-600 dark:bg-cyan-400 animate-ping" />
                    <span>Zaalima Security Gateway processing & scanning request...</span>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Chat Input Bar */}
          <ChatInput onSendMessage={handleSendMessage} isLoading={isLoading} />
        </main>
      </div>

      {/* Auth Settings Modal */}
      <AuthModal
        isOpen={isAuthModalOpen}
        onClose={() => setIsAuthModalOpen(false)}
        auth={auth}
        onSaveAuth={saveAuthSettings}
      />
    </div>
  );
}
