/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useTransition, useMemo } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Mail,
  Globe,
  Lock,
  Trash2,
  Copy,
  Check,
  ExternalLink,
  RefreshCw,
  Search,
  Sparkles,
  Terminal,
  Activity,
  AlertCircle,
  FileCheck,
  Share2
} from 'lucide-react';
import {
  analyzeInput,
  PRESET_EXAMPLES,
  type AnalysisResult,
  extractDomain,
  extractUrlsFromText
} from './lib/detector';

export default function App() {
  const [mode, setMode] = useState<'message' | 'url'>('message');
  const [inputText, setInputText] = useState<string>('');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [copiedReport, setCopiedReport] = useState<boolean>(false);
  const [completedSteps, setCompletedSteps] = useState<Record<string, boolean>>({});
  const [, startTransition] = useTransition();

  // Traiter l'analyse
  const handleAnalyze = () => {
    if (!inputText.trim()) return;
    setIsScanning(true);
    // Simulation d'un scan cyber réaliste (350ms pour feedback sensoriel)
    setTimeout(() => {
      startTransition(() => {
        const analysis = analyzeInput(inputText, mode);
        setResult(analysis);
        setIsScanning(false);
        setCompletedSteps({});
      });
    }, 350);
  };

  // Charger un préréglage
  const handleLoadPreset = (preset: typeof PRESET_EXAMPLES[number]) => {
    setMode(preset.mode);
    setInputText(preset.text);
    setIsScanning(true);
    setTimeout(() => {
      startTransition(() => {
        const analysis = analyzeInput(preset.text, preset.mode);
        setResult(analysis);
        setIsScanning(false);
        setCompletedSteps({});
      });
    }, 250);
  };

  // Réinitialiser
  const handleClear = () => {
    setInputText('');
    setResult(null);
    setCompletedSteps({});
  };

  // Copier le rapport d'incident
  const handleCopyReport = () => {
    if (!result) return;
    const report = [
      `=== RAPPORT D'ANALYSE PHIS GUARD ===`,
      `Date & Heure : ${result.timestamp}`,
      `Type analysé : ${result.analyzedType === 'message' ? 'Message (E-mail / SMS)' : 'URL / Domaine'}`,
      `Score de Risque : ${result.score}/100 [${result.status.toUpperCase()}]`,
      `Synthèse : ${result.executiveSummary}`,
      ``,
      `--- SCORES SECTORIELS ---`,
      `- Manipulation & Urgence : ${result.categories.urgency.score}/100 (${result.categories.urgency.label})`,
      `- Usurpation & Typosquatting : ${result.categories.brandImpersonation.score}/100 (${result.categories.brandImpersonation.label})`,
      `- Collecte Données Sensibles : ${result.categories.sensitiveData.score}/100 (${result.categories.sensitiveData.label})`,
      `- Anomalies Techniques : ${result.categories.technical.score}/100 (${result.categories.technical.label})`,
      ``,
      `--- ALERTES RELEVÉES (${result.alerts.length}) ---`,
      ...result.alerts.map(a => `• [${a.severity.toUpperCase()}] ${a.title} : ${a.description}`),
      ``,
      `--- CONSIGNES DE SÉCURITÉ CONSEILLÉES ---`,
      ...result.advices.map(ad => `✓ ${ad.text}`)
    ].join('\n');

    navigator.clipboard.writeText(report).then(() => {
      setCopiedReport(true);
      setTimeout(() => setCopiedReport(false), 2500);
    });
  };

  // Toggle checklist
  const toggleStep = (key: string) => {
    setCompletedSteps(prev => ({ ...prev, [key]: !prev[key] }));
  };

  // Calcul visuel de la jauge (arc de cercle SVG)
  const gaugeMetrics = useMemo(() => {
    if (!result) return null;
    const score = result.score;
    // Rayon 64, périmètre d'un demi-cercle: PI * r = ~201
    const radius = 60;
    const circumference = Math.PI * radius;
    const offset = circumference - (score / 100) * circumference;
    return { radius, circumference, offset };
  }, [result]);

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 antialiased flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Cyber Grid Ambient Background */}
      <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:24px_24px] opacity-25 pointer-events-none -z-10" />

      {/* Header */}
      <header id="app-header" className="border-b border-slate-800/80 bg-[#0b1120]/90 backdrop-blur sticky top-0 z-40">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 py-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-sm shadow-cyan-950">
              <Shield className="w-5 h-5 stroke-[2.2]" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xl font-extrabold tracking-tight text-white">Phis Guard</span>
                <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-cyan-950 border border-cyan-500/40 text-cyan-300 font-mono">
                  CYBER-DEFENSE
                </span>
              </div>
              <p className="text-xs text-slate-400 font-normal">
                Détecteur intelligent de tentatives de phishing et menaces en ligne
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 self-start sm:self-auto">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-slate-900 border border-slate-800 text-xs text-slate-300">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="font-mono text-slate-400">Heuristique KillPhish active</span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-6xl w-full mx-auto px-4 sm:px-6 py-8 flex-1 flex flex-col gap-8">
        
        {/* Intro & Preset Bar */}
        <section id="preset-section" className="flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
              <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
              <span>Tester rapidement un cas réel pré-configuré :</span>
            </div>
            <span className="text-xs text-slate-500 hidden md:inline">Cliquez pour tester instantanément</span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
            {PRESET_EXAMPLES.map((preset) => {
              const isDanger = preset.risk === 'danger';
              return (
                <button
                  key={preset.id}
                  id={`btn-preset-${preset.id}`}
                  onClick={() => handleLoadPreset(preset)}
                  className="flex flex-col text-left p-2.5 rounded-lg bg-slate-900/90 hover:bg-slate-800/90 border border-slate-800 hover:border-slate-700 transition duration-150 group cursor-pointer"
                >
                  <span className="text-[11px] font-mono text-slate-400 truncate mb-1">
                    {preset.category}
                  </span>
                  <span className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300 truncate">
                    {preset.title}
                  </span>
                  <div className="mt-2 flex items-center gap-1.5">
                    <span className={`w-1.5 h-1.5 rounded-full ${isDanger ? 'bg-rose-500' : 'bg-emerald-500'}`} />
                    <span className="text-[10px] text-slate-400">
                      {isDanger ? 'Menace' : 'Légitime'}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
        </section>

        {/* Input Card Container */}
        <section id="input-card" className="rounded-xl border border-slate-800 bg-[#0d1424] shadow-xl overflow-hidden">
          {/* Tabs Switcher */}
          <div className="flex border-b border-slate-800/90 bg-[#090e1a]">
            <button
              id="tab-mode-message"
              onClick={() => {
                setMode('message');
              }}
              className={`flex-1 py-3.5 px-4 text-xs sm:text-sm font-semibold flex items-center justify-center gap-2 border-b-2 transition duration-150 cursor-pointer ${
                mode === 'message'
                  ? 'border-cyan-400 text-cyan-300 bg-slate-900/40'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/20'
              }`}
            >
              <Mail className="w-4 h-4" />
              <span>Analyser un Message (E-mail / SMS)</span>
            </button>
            <button
              id="tab-mode-url"
              onClick={() => {
                setMode('url');
              }}
              className={`flex-1 py-3.5 px-4 text-xs sm:text-sm font-semibold flex items-center justify-center gap-2 border-b-2 transition duration-150 cursor-pointer ${
                mode === 'url'
                  ? 'border-cyan-400 text-cyan-300 bg-slate-900/40'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/20'
              }`}
            >
              <Globe className="w-4 h-4" />
              <span>Analyser une URL / Domaine</span>
            </button>
          </div>

          {/* Input Area */}
          <div className="p-4 sm:p-6 flex flex-col gap-4">
            <div className="flex items-center justify-between">
              <label htmlFor="threat-input" className="text-xs sm:text-sm font-medium text-slate-300 flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                {mode === 'message' ? 'Contenu textuel du message suspect :' : 'Adresse web complète ou domaine :'}
              </label>
              {inputText && (
                <button
                  id="btn-clear-input"
                  onClick={handleClear}
                  className="text-xs text-slate-400 hover:text-rose-400 flex items-center gap-1 transition cursor-pointer"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  Effacer
                </button>
              )}
            </div>

            {mode === 'message' ? (
              <textarea
                id="threat-input"
                rows={5}
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                placeholder="Collez ici le texte suspect de l'e-mail ou du SMS reçu (ex: « Chronopost : Votre colis est bloqué pour taxe de 1.99€ sous 24h, régularisez sur http://... »)"
                className="w-full bg-[#080d1a] border border-slate-700/80 rounded-lg p-3.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 transition resize-y font-mono leading-relaxed"
              />
            ) : (
              <div className="relative">
                <input
                  id="threat-input"
                  type="text"
                  value={inputText}
                  onChange={(e) => setInputText(e.target.value)}
                  placeholder="https://paypal-securite-connexion.com/verification"
                  className="w-full bg-[#080d1a] border border-slate-700/80 rounded-lg py-3.5 px-4 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 transition font-mono"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleAnalyze();
                  }}
                />
              </div>
            )}

            {/* Bottom Actions Bar */}
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 pt-2">
              <div className="text-xs text-slate-400 font-mono">
                {inputText.length} caractère(s) • {mode === 'message' ? 'Analyse psychologique & linguistique' : 'Analyse DNS & Typosquatting'}
              </div>

              <button
                id="btn-run-analysis"
                onClick={handleAnalyze}
                disabled={!inputText.trim() || isScanning}
                className="inline-flex items-center justify-center gap-2.5 px-6 py-3 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold text-sm shadow-md shadow-cyan-950 transition duration-150 cursor-pointer"
              >
                {isScanning ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin text-white" />
                    <span>Scan cyber en cours...</span>
                  </>
                ) : (
                  <>
                    <ShieldAlert className="w-4 h-4 text-cyan-100" />
                    <span>Analyser la menace</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </section>

        {/* Dashboard de Résultat */}
        {result && (
          <div id="result-dashboard" className="flex flex-col gap-6 animate-fadeIn">
            
            {/* Top Risk Header Card with Circular/Semicircular Gauge */}
            <section
              id="risk-score-card"
              className={`rounded-xl border p-6 shadow-xl ${
                result.status === 'Élevé'
                  ? 'border-rose-800/80 bg-gradient-to-b from-rose-950/40 to-[#0d1424]'
                  : result.status === 'Modéré'
                  ? 'border-amber-800/80 bg-gradient-to-b from-amber-950/30 to-[#0d1424]'
                  : 'border-emerald-800/80 bg-gradient-to-b from-emerald-950/30 to-[#0d1424]'
              }`}
            >
              <div className="flex flex-col lg:flex-row items-center justify-between gap-6">
                
                {/* Visual Gauge */}
                <div className="flex items-center gap-6">
                  <div className="relative flex items-center justify-center w-36 h-36">
                    {/* SVG Gauge */}
                    <svg className="w-36 h-36 -rotate-90 transform" viewBox="0 0 140 140">
                      {/* Track Background */}
                      <circle
                        cx="70"
                        cy="70"
                        r="54"
                        fill="transparent"
                        stroke="#1e293b"
                        strokeWidth="12"
                      />
                      {/* Colored Progress Ring */}
                      <circle
                        cx="70"
                        cy="70"
                        r="54"
                        fill="transparent"
                        stroke={
                          result.status === 'Élevé'
                            ? '#f43f5e'
                            : result.status === 'Modéré'
                            ? '#f59e0b'
                            : '#10b981'
                        }
                        strokeWidth="12"
                        strokeDasharray={2 * Math.PI * 54}
                        strokeDashoffset={2 * Math.PI * 54 * (1 - result.score / 100)}
                        strokeLinecap="round"
                        className="transition-all duration-700 ease-out"
                      />
                    </svg>

                    {/* Central Value */}
                    <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                      <span className="text-3xl font-extrabold font-mono text-white tracking-tight">
                        {result.score}
                      </span>
                      <span className="text-[10px] uppercase font-mono text-slate-400">/ 100</span>
                      <span className="text-[11px] font-semibold text-slate-300">Indice Risque</span>
                    </div>
                  </div>

                  <div className="flex flex-col gap-2">
                    <div className="flex items-center gap-2">
                      <span
                        className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 ${
                          result.status === 'Élevé'
                            ? 'bg-rose-950 text-rose-300 border border-rose-700/80'
                            : result.status === 'Modéré'
                            ? 'bg-amber-950 text-amber-300 border border-amber-700/80'
                            : 'bg-emerald-950 text-emerald-300 border border-emerald-700/80'
                        }`}
                      >
                        {result.status === 'Élevé' ? (
                          <ShieldAlert className="w-3.5 h-3.5" />
                        ) : result.status === 'Modéré' ? (
                          <AlertTriangle className="w-3.5 h-3.5" />
                        ) : (
                          <ShieldCheck className="w-3.5 h-3.5" />
                        )}
                        Risque {result.status}
                      </span>
                      <span className="text-xs font-mono text-slate-400">
                        Scan #{Math.floor(1000 + Math.random() * 9000)} • {result.timestamp}
                      </span>
                    </div>

                    <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
                      {result.status === 'Élevé'
                        ? 'Menace Critique de Phishing Confirmée'
                        : result.status === 'Modéré'
                        ? 'Indicateurs Suspects Détectés (Vigilance)'
                        : 'Aucun Risque Majeur Identifié'}
                    </h2>

                    <p className="text-xs sm:text-sm text-slate-300 max-w-xl leading-relaxed">
                      {result.executiveSummary}
                    </p>
                  </div>
                </div>

                {/* Quick Share / Export Actions */}
                <div className="flex sm:flex-col gap-2 w-full lg:w-auto">
                  <button
                    id="btn-copy-report"
                    onClick={handleCopyReport}
                    className="flex-1 lg:flex-none px-4 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-semibold text-slate-200 flex items-center justify-center gap-2 transition cursor-pointer"
                  >
                    {copiedReport ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span className="text-emerald-300">Rapport copié !</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copier le rapport</span>
                      </>
                    )}
                  </button>
                  <button
                    id="btn-new-analysis"
                    onClick={handleClear}
                    className="flex-1 lg:flex-none px-4 py-2.5 rounded-lg bg-slate-900/80 hover:bg-slate-800 border border-slate-800 text-xs font-medium text-slate-400 hover:text-slate-200 flex items-center justify-center gap-2 transition cursor-pointer"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>Nouvelle analyse</span>
                  </button>
                </div>
              </div>
            </section>

            {/* 4 Pillars of Cyber Evaluation (KillPhish AI Matrix) */}
            <section id="evaluation-pillars" className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {/* 1. Urgence & Manipulation */}
              <div className="rounded-xl border border-slate-800 bg-[#0d1424] p-4 flex flex-col justify-between gap-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    Manipulation & Urgence
                  </span>
                  <Activity className={`w-4 h-4 ${result.categories.urgency.score >= 40 ? 'text-rose-400' : 'text-slate-500'}`} />
                </div>
                <div>
                  <div className="flex items-baseline gap-2">
                    <span className="text-2xl font-bold font-mono text-white">
                      {result.categories.urgency.score}
                    </span>
                    <span className="text-xs text-slate-500 font-mono">/100</span>
                    <span className={`text-xs font-semibold ml-auto ${result.categories.urgency.score >= 40 ? 'text-rose-400' : 'text-slate-400'}`}>
                      {result.categories.urgency.label}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1 line-clamp-2">
                    {result.categories.urgency.details}
                  </p>
                </div>
                <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${result.categories.urgency.score >= 40 ? 'bg-rose-500' : result.categories.urgency.score >= 20 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                    style={{ width: `${result.categories.urgency.score}%` }}
                  />
                </div>
              </div>

              {/* 2. Usurpation & Typosquatting */}
              <div className="rounded-xl border border-slate-800 bg-[#0d1424] p-4 flex flex-col justify-between gap-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    Usurpation de Marque
                  </span>
                  <Globe className={`w-4 h-4 ${result.categories.brandImpersonation.score >= 40 ? 'text-rose-400' : 'text-slate-500'}`} />
                </div>
                <div>
                  <div className="flex items-baseline gap-2">
                    <span className="text-2xl font-bold font-mono text-white">
                      {result.categories.brandImpersonation.score}
                    </span>
                    <span className="text-xs text-slate-500 font-mono">/100</span>
                    <span className={`text-xs font-semibold ml-auto ${result.categories.brandImpersonation.score >= 40 ? 'text-rose-400' : 'text-slate-400'}`}>
                      {result.categories.brandImpersonation.label}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1 line-clamp-2">
                    {result.categories.brandImpersonation.details}
                  </p>
                </div>
                <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${result.categories.brandImpersonation.score >= 40 ? 'bg-rose-500' : result.categories.brandImpersonation.score >= 20 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                    style={{ width: `${result.categories.brandImpersonation.score}%` }}
                  />
                </div>
              </div>

              {/* 3. Données Sensibles */}
              <div className="rounded-xl border border-slate-800 bg-[#0d1424] p-4 flex flex-col justify-between gap-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    Données Sensibles
                  </span>
                  <Lock className={`w-4 h-4 ${result.categories.sensitiveData.score >= 40 ? 'text-rose-400' : 'text-slate-500'}`} />
                </div>
                <div>
                  <div className="flex items-baseline gap-2">
                    <span className="text-2xl font-bold font-mono text-white">
                      {result.categories.sensitiveData.score}
                    </span>
                    <span className="text-xs text-slate-500 font-mono">/100</span>
                    <span className={`text-xs font-semibold ml-auto ${result.categories.sensitiveData.score >= 40 ? 'text-rose-400' : 'text-slate-400'}`}>
                      {result.categories.sensitiveData.label}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1 line-clamp-2">
                    {result.categories.sensitiveData.details}
                  </p>
                </div>
                <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${result.categories.sensitiveData.score >= 40 ? 'bg-rose-500' : result.categories.sensitiveData.score >= 20 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                    style={{ width: `${result.categories.sensitiveData.score}%` }}
                  />
                </div>
              </div>

              {/* 4. Risque Technique & Liens */}
              <div className="rounded-xl border border-slate-800 bg-[#0d1424] p-4 flex flex-col justify-between gap-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    Contrôle Technique
                  </span>
                  <Terminal className={`w-4 h-4 ${result.categories.technical.score >= 40 ? 'text-rose-400' : 'text-slate-500'}`} />
                </div>
                <div>
                  <div className="flex items-baseline gap-2">
                    <span className="text-2xl font-bold font-mono text-white">
                      {result.categories.technical.score}
                    </span>
                    <span className="text-xs text-slate-500 font-mono">/100</span>
                    <span className={`text-xs font-semibold ml-auto ${result.categories.technical.score >= 40 ? 'text-rose-400' : 'text-slate-400'}`}>
                      {result.categories.technical.label}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1 line-clamp-2">
                    {result.categories.technical.details}
                  </p>
                </div>
                <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${result.categories.technical.score >= 40 ? 'bg-rose-500' : result.categories.technical.score >= 20 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                    style={{ width: `${result.categories.technical.score}%` }}
                  />
                </div>
              </div>
            </section>

            {/* Split Grid: Alertes Relevées vs Inspecteur & Conseils */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              
              {/* Alertes Détaillées (7 cols) */}
              <section id="alerts-section" className="lg:col-span-7 flex flex-col gap-4">
                <div className="rounded-xl border border-slate-800 bg-[#0d1424] p-5">
                  <div className="flex items-center justify-between mb-4 border-b border-slate-800/80 pb-3">
                    <h3 className="text-sm font-bold text-white flex items-center gap-2">
                      <AlertCircle className="w-4 h-4 text-cyan-400" />
                      <span>Alertes Cyber et Indicateurs Détectés ({result.alerts.length})</span>
                    </h3>
                    <span className="text-xs font-mono text-slate-400">Évaluation KillPhish AI</span>
                  </div>

                  {result.alerts.length === 0 ? (
                    <div className="py-8 text-center text-slate-400 text-xs">
                      <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
                      Aucun indicateur de menace ni comportement suspect répertorié.
                    </div>
                  ) : (
                    <div className="flex flex-col gap-3">
                      {result.alerts.map((alert) => {
                        const isHigh = alert.severity === 'high';
                        const isMed = alert.severity === 'medium';
                        const isSafe = alert.severity === 'safe';

                        return (
                          <div
                            key={alert.id}
                            className={`p-3.5 rounded-lg border flex flex-col gap-2 ${
                              isHigh
                                ? 'bg-rose-950/30 border-rose-900/60'
                                : isMed
                                ? 'bg-amber-950/20 border-amber-900/50'
                                : isSafe
                                ? 'bg-emerald-950/20 border-emerald-900/50'
                                : 'bg-slate-900 border-slate-800'
                            }`}
                          >
                            <div className="flex items-center justify-between gap-2">
                              <span className="text-xs font-bold text-slate-100 flex items-center gap-1.5">
                                {isHigh ? (
                                  <AlertTriangle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                                ) : isMed ? (
                                  <AlertCircle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                                ) : (
                                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                                )}
                                {alert.title}
                              </span>

                              <span
                                className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                                  isHigh
                                    ? 'bg-rose-950 text-rose-300 border border-rose-800/80'
                                    : isMed
                                    ? 'bg-amber-950 text-amber-300 border border-amber-800/80'
                                    : 'bg-emerald-950 text-emerald-300 border border-emerald-800/80'
                                }`}
                              >
                                {isHigh ? 'Critique' : isMed ? 'Vigilance' : 'Sûr'}
                              </span>
                            </div>

                            <p className="text-xs text-slate-300 leading-relaxed">
                              {alert.description}
                            </p>

                            {alert.snippet && (
                              <div className="text-[11px] font-mono text-cyan-300 bg-slate-950/70 px-2.5 py-1 rounded border border-slate-800 inline-block overflow-x-auto">
                                Cible / Échantillon : {alert.snippet}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Inspecteur Technique de l'Entrée */}
                <div className="rounded-xl border border-slate-800 bg-[#0d1424] p-5">
                  <h3 className="text-sm font-bold text-white flex items-center gap-2 mb-3 border-b border-slate-800/80 pb-3">
                    <FileCheck className="w-4 h-4 text-cyan-400" />
                    <span>Inspection Technique & Données Brutes</span>
                  </h3>

                  <div className="flex flex-col gap-3">
                    <div className="p-3 bg-[#080d1a] rounded-lg border border-slate-800 font-mono text-xs text-slate-300 break-all leading-relaxed">
                      <div className="text-[11px] text-slate-500 mb-1">Contenu soumis :</div>
                      « {result.inputSnippet} »
                    </div>

                    {result.extractedUrls && result.extractedUrls.length > 0 && (
                      <div className="p-3 bg-[#080d1a] rounded-lg border border-slate-800 flex flex-col gap-2">
                        <div className="text-[11px] text-slate-400 font-semibold uppercase tracking-wider">
                          URLs ou Domaines Identifiés ({result.extractedUrls.length}) :
                        </div>
                        {result.extractedUrls.map((url, idx) => {
                          const domainInfo = extractDomain(url);
                          return (
                            <div key={idx} className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-xs font-mono bg-slate-900/80 p-2 rounded border border-slate-800">
                              <span className="text-cyan-300 truncate">{url}</span>
                              <span className="text-[11px] text-slate-400 shrink-0">
                                [Hôte: {domainInfo.hostname} • Protocole: {domainInfo.protocol}]
                              </span>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                </div>
              </section>

              {/* Gestes Réflexes & Consignes Pratiques (5 cols) */}
              <section id="safety-checklist-section" className="lg:col-span-5 flex flex-col gap-4">
                <div className="rounded-xl border border-slate-800 bg-[#0d1424] p-5 h-full flex flex-col">
                  <div className="flex items-center justify-between mb-4 border-b border-slate-800/80 pb-3">
                    <h3 className="text-sm font-bold text-white flex items-center gap-2">
                      <Shield className="w-4 h-4 text-cyan-400" />
                      <span>Consignes Pratiques & Conduite à Tenir</span>
                    </h3>
                    <span className="text-xs font-mono text-slate-400">Recommandations Cyber</span>
                  </div>

                  <p className="text-xs text-slate-400 mb-4 leading-relaxed">
                    Appliquez immédiatement les gestes barrières de sécurité ci-dessous face à cette situation :
                  </p>

                  <div className="flex flex-col gap-3 flex-1">
                    {result.advices.map((advice, idx) => {
                      const key = `step-${idx}`;
                      const isChecked = !!completedSteps[key];

                      return (
                        <div
                          key={idx}
                          onClick={() => toggleStep(key)}
                          className={`p-3 rounded-lg border flex items-start gap-3 transition cursor-pointer ${
                            isChecked
                              ? 'bg-emerald-950/30 border-emerald-800/50 text-slate-200'
                              : advice.urgent
                              ? 'bg-rose-950/20 border-rose-900/40 text-slate-200 hover:bg-rose-950/30'
                              : 'bg-slate-900/60 border-slate-800 text-slate-300 hover:bg-slate-900'
                          }`}
                        >
                          <input
                            type="checkbox"
                            checked={isChecked}
                            onChange={() => {}}
                            className="mt-0.5 rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-0 cursor-pointer"
                          />
                          <div className="flex-1 text-xs leading-relaxed">
                            <span className={isChecked ? 'line-through text-slate-400' : ''}>
                              {advice.text}
                            </span>
                            {advice.urgent && !isChecked && (
                              <span className="ml-2 text-[10px] font-bold text-rose-400 uppercase font-mono">
                                [PRIORITAIRE]
                              </span>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  {/* Organismes de Signalement Officiels */}
                  <div className="mt-6 pt-4 border-t border-slate-800/80">
                    <div className="text-xs font-bold text-slate-300 mb-2">
                      Plateformes officielles de signalement :
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                      <div className="p-2 bg-slate-950 rounded border border-slate-800 text-slate-400">
                        <span className="text-cyan-400 font-bold block">Phishing Initiative</span>
                        Signaler une URL frauduleuse
                      </div>
                      <div className="p-2 bg-slate-950 rounded border border-slate-800 text-slate-400">
                        <span className="text-cyan-400 font-bold block">Signal-Spam</span>
                        Signaler un e-mail suspect
                      </div>
                      <div className="p-2 bg-slate-950 rounded border border-slate-800 text-slate-400">
                        <span className="text-cyan-400 font-bold block">33700</span>
                        Signaler un SMS frauduleux
                      </div>
                      <div className="p-2 bg-slate-950 rounded border border-slate-800 text-slate-400">
                        <span className="text-cyan-400 font-bold block">THESEE / Perceval</span>
                        Signaler une fraude bancaire
                      </div>
                    </div>
                  </div>
                </div>
              </section>
            </div>
          </div>
        )}

        {/* Informative Cyber Education Box when no result */}
        {!result && (
          <section id="educational-banner" className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="rounded-xl border border-slate-800 bg-[#0d1424] p-5 flex flex-col gap-2">
              <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-700/50 flex items-center justify-center text-cyan-400 mb-1">
                <AlertTriangle className="w-4 h-4" />
              </div>
              <h4 className="text-sm font-bold text-white">Fausse Urgence</h4>
              <p className="text-xs text-slate-400 leading-relaxed">
                Les pirates instaurent une panique artificielle (« sous 24h », « compte clôturé ») pour paralyser l'esprit critique de leur victime.
              </p>
            </div>

            <div className="rounded-xl border border-slate-800 bg-[#0d1424] p-5 flex flex-col gap-2">
              <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-700/50 flex items-center justify-center text-cyan-400 mb-1">
                <Globe className="w-4 h-4" />
              </div>
              <h4 className="text-sm font-bold text-white">Typosquatting & Marque</h4>
              <p className="text-xs text-slate-400 leading-relaxed">
                Repérage des noms de domaine trompeurs imitant les banques, les impôts ou les services de livraison avec des tirets ou extensions suspectes.
              </p>
            </div>

            <div className="rounded-xl border border-slate-800 bg-[#0d1424] p-5 flex flex-col gap-2">
              <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-700/50 flex items-center justify-center text-cyan-400 mb-1">
                <Lock className="w-4 h-4" />
              </div>
              <h4 className="text-sm font-bold text-white">Vol de Données Sensibles</h4>
              <p className="text-xs text-slate-400 leading-relaxed">
                Analyse des sollicitations de mots de passe, codes de sécurité SMS (OTP), cartes bancaires ou pièces d'identité officielles.
              </p>
            </div>
          </section>
        )}
      </main>

      {/* Footer */}
      <footer id="app-footer" className="border-t border-slate-800/80 bg-[#0b1120] py-6 text-xs text-slate-400 mt-auto">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            <span className="font-semibold text-slate-300">Phis Guard</span>
            <span>— Moteur heuristique d'analyse et de protection anti-phishing</span>
          </div>
          <div className="text-slate-500 font-mono text-[11px]">
            Inspiré par ScamAdviser, CheckPhish & KillPhish AI • Traitement local et confidentiel
          </div>
        </div>
      </footer>
    </div>
  );
}
