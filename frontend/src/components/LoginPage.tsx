'use client';

import React, { useState } from 'react';
import { ShieldCheck, Lock, User, AlertCircle, ArrowRight, Loader2, Sparkles, Eye, EyeOff } from 'lucide-react';
import { loginToGateway } from '../lib/api';
import { GatewayAuth } from '../lib/types';
import { ThemeToggle } from './ThemeToggle';

interface LoginPageProps {
  onLoginSuccess: (authData: GatewayAuth) => void;
}

export const LoginPage: React.FC<LoginPageProps> = ({ onLoginSuccess }) => {
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!identifier.trim() || !password || isLoading) return;

    setIsLoading(true);
    setErrorMsg('');

    const response = await loginToGateway(identifier, password);
    setIsLoading(false);

    if (response.success) {
      onLoginSuccess({
        apiKey: response.access_token,
        userId: response.user.username,
        user: response.user,
        allowedModels: response.allowed_models,
        apiUrl: 'http://127.0.0.1:8081',
      });
    } else {
      setErrorMsg(response.message || 'Invalid credentials or unauthorized access');
    }
  };

  const quickFillAccount = (id: string, pass: string) => {
    setIdentifier(id);
    setPassword(pass);
    setErrorMsg('');
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex items-center justify-center p-4 relative overflow-hidden font-sans transition-colors">
      {/* Absolute Theme Toggle at top right */}
      <div className="absolute top-4 right-4 z-20">
        <ThemeToggle />
      </div>

      {/* Ambient background glow */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-cyan-500/10 dark:bg-cyan-600/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-1/4 left-1/3 w-80 h-80 bg-blue-500/10 dark:bg-blue-600/10 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-md space-y-6 relative z-10 animate-fade-in">
        {/* Zaalima Branding */}
        <div className="text-center space-y-3">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-600 text-white shadow-xl shadow-cyan-500/20 mb-1">
            <ShieldCheck className="w-8 h-8" />
          </div>
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-slate-900 dark:text-white flex items-center justify-center gap-2">
              <span>Zaalima</span>
              <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-cyan-50 dark:bg-cyan-500/10 text-cyan-700 dark:text-cyan-400 border border-cyan-200 dark:border-cyan-500/20">
                Gateway v1.0
              </span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Enterprise LLM & GenAI Security Gateway
            </p>
          </div>
        </div>

        {/* Login Card */}
        <div className="bg-white dark:bg-slate-900/90 backdrop-blur-xl border border-slate-200 dark:border-slate-800 rounded-3xl p-6 sm:p-8 shadow-xl dark:shadow-2xl space-y-6 transition-colors">
          <div className="space-y-1">
            <h2 className="text-base font-bold text-slate-900 dark:text-white">Sign In to Your Workspace</h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Role & department permissions are automatically retrieved upon authentication.
            </p>
          </div>

          {errorMsg && (
            <div className="p-3.5 rounded-xl bg-red-50 dark:bg-red-950/60 border border-red-200 dark:border-red-800/60 text-xs text-red-700 dark:text-red-300 flex items-start space-x-2.5 animate-shake">
              <AlertCircle className="w-4 h-4 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
              <span>{errorMsg}</span>
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-4">
            {/* Email / Username */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
                <User className="w-3.5 h-3.5 text-cyan-600 dark:text-cyan-400" />
                Email or Username
              </label>
              <input
                type="text"
                value={identifier}
                onChange={(e) => setIdentifier(e.target.value)}
                placeholder="e.g. employee@zaalima.in or admin@zaalima.in"
                className="w-full px-4 py-3 rounded-xl bg-slate-50 dark:bg-slate-950/90 border border-slate-300 dark:border-slate-800 text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all font-sans"
                required
              />
            </div>

            {/* Password */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-cyan-600 dark:text-cyan-400" />
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full pl-4 pr-10 py-3 rounded-xl bg-slate-50 dark:bg-slate-950/90 border border-slate-300 dark:border-slate-800 text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all font-mono"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:text-slate-500 dark:hover:text-slate-300 focus:outline-none transition-colors p-1 cursor-pointer"
                >
                  {showPassword ? (
                    <EyeOff className="w-4 h-4" />
                  ) : (
                    <Eye className="w-4 h-4" />
                  )}
                </button>
              </div>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isLoading || !identifier.trim() || !password}
              className={`w-full py-3 px-4 rounded-xl font-medium text-xs shadow-lg transition-all flex items-center justify-center space-x-2 cursor-pointer ${
                isLoading || !identifier.trim() || !password
                  ? 'bg-slate-200 dark:bg-slate-800 text-slate-400 dark:text-slate-500 cursor-not-allowed'
                  : 'bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-cyan-600/20'
              }`}
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin text-cyan-200" />
                  <span>Authenticating Account...</span>
                </>
              ) : (
                <>
                  <span>Sign In</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Quick Fill Test Accounts */}
          <div className="pt-3 border-t border-slate-200 dark:border-slate-800/80 space-y-2.5">
            <p className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 flex items-center gap-1">
              <Sparkles className="w-3 h-3 text-cyan-600 dark:text-cyan-400" /> Test Demo Accounts (Click to Fill):
            </p>

            <div className="grid grid-cols-2 gap-2 text-[11px]">
              <button
                type="button"
                onClick={() => quickFillAccount('employee@zaalima.in', 'Employee@123')}
                className="p-2 rounded-xl bg-slate-50 dark:bg-slate-950 hover:bg-slate-100 dark:hover:bg-slate-800/90 border border-slate-200 dark:border-slate-800 text-left transition-all group cursor-pointer"
              >
                <p className="font-semibold text-slate-800 dark:text-slate-200 group-hover:text-cyan-600 dark:group-hover:text-cyan-400">👤 Employee</p>
                <p className="text-[10px] text-slate-500 dark:text-slate-500">Engineering Dept</p>
              </button>

              <button
                type="button"
                onClick={() => quickFillAccount('finance@zaalima.in', 'Finance@123')}
                className="p-2 rounded-xl bg-slate-50 dark:bg-slate-950 hover:bg-slate-100 dark:hover:bg-slate-800/90 border border-slate-200 dark:border-slate-800 text-left transition-all group cursor-pointer"
              >
                <p className="font-semibold text-slate-800 dark:text-slate-200 group-hover:text-cyan-600 dark:group-hover:text-cyan-400">💼 Finance User</p>
                <p className="text-[10px] text-slate-500 dark:text-slate-500">Finance Dept</p>
              </button>

              <button
                type="button"
                onClick={() => quickFillAccount('analyst@zaalima.in', 'Analyst@123')}
                className="p-2 rounded-xl bg-cyan-50 dark:bg-cyan-950/40 hover:bg-cyan-100 dark:hover:bg-cyan-900/50 border border-cyan-200 dark:border-cyan-800/50 text-left transition-all group cursor-pointer"
              >
                <p className="font-semibold text-cyan-800 dark:text-cyan-300 group-hover:text-cyan-900 dark:group-hover:text-cyan-200">🛡️ Security Analyst</p>
                <p className="text-[10px] text-cyan-600 dark:text-cyan-400/70">SOC Dashboard Access</p>
              </button>

              <button
                type="button"
                onClick={() => quickFillAccount('admin@zaalima.in', 'Admin@123')}
                className="p-2 rounded-xl bg-blue-50 dark:bg-blue-950/40 hover:bg-blue-100 dark:hover:bg-blue-900/50 border border-blue-200 dark:border-blue-800/50 text-left transition-all group cursor-pointer"
              >
                <p className="font-semibold text-blue-800 dark:text-blue-300 group-hover:text-blue-900 dark:group-hover:text-blue-200">👑 Administrator</p>
                <p className="text-[10px] text-blue-600 dark:text-blue-400/70">SOC Dashboard Access</p>
              </button>
            </div>
          </div>
        </div>

        {/* Disclaimer */}
        <p className="text-center text-[11px] text-slate-500 dark:text-slate-500">
          Zaalima Security Gateway — Protected by Presidio DLP & DeBERTa ML Injection Defense.
        </p>
      </div>
    </div>
  );
};
