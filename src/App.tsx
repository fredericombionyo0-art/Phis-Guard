/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useTransition } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Globe,
  Mail,
  Lock,
  Copy,
  Check,
  RefreshCw,
  Search,
  Terminal,
  Activity,
  AlertCircle,
  FileCheck,
  X,
  ClipboardPaste,
  ArrowRight
} from 'lucide-react';
import {
  analyzeInput,
  type AnalysisResult,
  extractDomain
} from './lib/detector';

export default function App() {
  const [inputText, setInputText] = useState<string>('');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [copiedReport, setCopiedReport] = useState<boolean>(false);
  const [completedSteps, setCompletedSteps] = useState<Record<string, boolean>>({});
  const [, startTransition] = useTransition();

  // Traiter l'analyse (E-mail ou URL)
  const handleAnalyze = (overrideInput?: string) => {
    const target = (overrideInput ?? inputText).trim();
    if (!target) return;
    setIsScanning(true);

    // Détection automatique : URL vs E-mail / Message
    const isLikelyUrl = /^(https?:\/\/|[a-zA-Z0-9-]+\.[a-zA-Z]{2,})(\/[^\s]*)?$/i.test(target) && !target.includes(' ') && !target.includes('\n');
    const detectedType: 'url' | 'message' = isLikelyUrl ? 'url' : 'message';

    // Simulation d'un scan cyber réaliste (350ms pour feedback sensoriel)
    setTimeout(() => {
      startTransition(() => {
        const analysis = analyzeInput(target, detectedType);
        setResult(analysis);
        setIsScanning(false);
        setCompletedSteps({});
      });
    }, 350);
  };

  // Coller depuis le presse-papiers
  const handlePaste = async () => {
    try {
      if (navigator?.clipboard?.readText) {
        const text = await navigator.clipboard.readText();
        if (text) {
          setInputText(text.trim());
        }
      }
    } catch {
      // Ignorer si les permissions du presse-papiers sont restreintes dans l'iframe
    }
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

  return (
    <div className="min-h-screen bg-[#040816] text-slate-100 antialiased flex flex-col font-sans relative overflow-x-hidden selection:bg-cyan-500/30 selection:text-cyan-200">
      
      {/* --- FOND BLEU FONCÉ & LUMIÈRE CINÉMATOGRAPHIQUE --- */}
      {/* 1. Faisceau lumineux cinématographique descendant depuis le haut */}
      <div 
        className="absolute top-0 left-1/2 -translate-x-1/2 w-[900px] h-[550px] bg-[radial-gradient(ellipse_75%_50%_at_50%_0%,rgba(34,211,238,0.22)_0%,rgba(14,116,144,0.12)_35%,rgba(3,7,18,0)_75%)] pointer-events-none -z-10 cinematic-beam-anim"
      />
      {/* 2. Halo d'ambiance centrale douce derrière la zone suspendue */}
      <div 
        className="absolute top-44 left-1/2 -translate-x-1/2 w-[700px] h-[350px] bg-[radial-gradient(circle,rgba(56,189,248,0.14)_0%,rgba(99,102,241,0.06)_45%,transparent_70%)] pointer-events-none -z-10 blur-2xl" 
      />
      {/* 3. Texture subtile cyber en arrière-plan */}
      <div 
        className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:32px_32px] opacity-15 pointer-events-none -z-20" 
      />

      {/* Header épuré */}
      <header id="app-header" className="border-b border-slate-800/60 bg-[#04091a]/80 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 py-3.5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-cyan-950/90 border border-cyan-500/50 flex items-center justify-center text-cyan-400 shadow-sm shadow-cyan-950">
              <Shield className="w-5 h-5 stroke-[2.2]" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-lg font-extrabold tracking-tight text-white">Phis Guard</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-cyan-950/80 border border-cyan-500/30 text-cyan-300 font-mono">
                  CYBER-DEFENSE
                </span>
              </div>
              <p className="text-[11px] text-slate-400 hidden sm:block">
                Détecteur de phishing spécialisé sur E-mails & URLs
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-900/90 border border-slate-800 text-xs text-slate-300">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="font-mono text-[11px] text-slate-400">Heuristique Active</span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-5xl w-full mx-auto px-4 sm:px-6 py-8 sm:py-12 flex-1 flex flex-col gap-10">
        
        {/* --- ZONE CENTRALE : BARRE DE RECHERCHE SUSPENDUE DANS L'ESPACE --- */}
        <section id="hero-search-section" className="flex flex-col items-center text-center gap-6 pt-2 sm:pt-6">
          <div className="flex flex-col gap-2 max-w-xl">
            <h1 className="text-2xl sm:text-4xl font-extrabold text-white tracking-tight leading-tight">
              Détecteur de Phishing <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-sky-300 to-indigo-300">E-mails & URLs</span>
            </h1>
          </div>

          {/* Container Suspendu avec jeu de lumière successif sur les bords */}
          <div className="w-full max-w-2xl floating-search-container">
            <div className="glowing-border-wrapper">
              <div className="glowing-border-inner p-2 sm:p-2.5 flex items-center gap-2 sm:gap-3">
                {/* Icônes de détection E-mail & URL */}
                <div className="pl-2 sm:pl-3 flex items-center gap-1 text-cyan-400 shrink-0">
                  <Mail className="w-4 h-4 text-cyan-400/90" />
                  <span className="text-slate-600 text-xs">/</span>
                  <Globe className="w-4 h-4 text-sky-400/90" />
                </div>

                {/* Champ de saisie E-mail / URL */}
                <input
                  id="search-url-input"
                  type="text"
                  value={inputText}
                  onChange={(e) => setInputText(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleAnalyze();
                  }}
                  placeholder="Collez une URL ou un e-mail suspect (ex: https://... ou contact@...)..."
                  className="w-full bg-transparent border-none text-sm sm:text-base text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-0 font-mono py-2"
                  autoFocus
                />

                {/* Actions secondaires rapides (Effacer / Coller) */}
                <div className="flex items-center gap-1.5 shrink-0">
                  {inputText ? (
                    <button
                      id="btn-clear-url"
                      onClick={handleClear}
                      title="Effacer"
                      className="p-1.5 rounded-md text-slate-400 hover:text-rose-400 hover:bg-slate-800/80 transition cursor-pointer"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  ) : (
                    <button
                      id="btn-paste-url"
                      onClick={handlePaste}
                      title="Coller l'e-mail ou l'URL"
                      className="hidden sm:inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md text-[11px] font-medium text-slate-400 hover:text-cyan-300 hover:bg-slate-800/80 transition cursor-pointer border border-slate-700/60"
                    >
                      <ClipboardPaste className="w-3.5 h-3.5" />
                      <span>Coller</span>
                    </button>
                  )}

                  {/* Bouton Principal d'action */}
                  <button
                    id="btn-submit-analysis"
                    onClick={() => handleAnalyze()}
                    disabled={!inputText.trim() || isScanning}
                    className="inline-flex items-center justify-center gap-2 px-4 sm:px-6 py-2.5 sm:py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-40 disabled:cursor-not-allowed text-white font-semibold text-xs sm:text-sm shadow-lg shadow-cyan-950 transition duration-200 cursor-pointer shrink-0"
                  >
                    {isScanning ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        <span className="hidden sm:inline">Analyse...</span>
                      </>
                    ) : (
                      <>
                        <ShieldAlert className="w-4 h-4 text-cyan-100" />
                        <span>Analyser</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* --- RÉSULTAT DE LA REQUÊTE (NON MODIFIÉ) --- */}
        {result && (
          <div id="result-dashboard" className="flex flex-col gap-6 animate-fadeIn">
            
            {/* Top Risk Header Card with Circular Gauge */}
            <section
              id="risk-score-card"
              className={`rounded-xl border p-6 shadow-2xl backdrop-blur ${
                result.status === 'Élevé'
                  ? 'border-rose-800/80 bg-gradient-to-b from-rose-950/40 to-[#0d1424]'
                  : result.status === 'Modéré'
                  ? 'border-amber-800/80 bg-gradient-to-b from-amber-950/30 to-[#0d1424]'
                  : 'border-emerald-800/80 bg-gradient-to-b from-emerald-950/30 to-[#0d1424]'
              }`}
            >
              <div className="flex flex-col lg:flex-row items-center justify-between gap-6">
                
                {/* Visual Gauge */}
                <div className="flex flex-col sm:flex-row items-center gap-6 text-center sm:text-left">
                  <div className="relative flex items-center justify-center w-36 h-36 shrink-0">
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
                    <div className="flex items-center justify-center sm:justify-start gap-2">
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

        {/* Fin section de résultats */}
      </main>
    </div>
  );
}
