/**
 * Moteur d'analyse cyber et détection de phishing - Phis Guard
 * Inspiré par ScamAdviser, CheckPhish & KillPhish AI
 */

export interface BrandTarget {
  name: string;
  category: string;
  officialDomains: string[];
  keywords: string[];
}

export interface DetectedAlert {
  id: string;
  category: 'urgency' | 'brand' | 'sensitive_data' | 'technical' | 'safe';
  severity: 'high' | 'medium' | 'low' | 'safe';
  title: string;
  description: string;
  snippet?: string;
}

export interface SecurityAdvice {
  icon: 'shield-alert' | 'trash' | 'external-link' | 'lock' | 'flag' | 'check';
  text: string;
  urgent?: boolean;
}

export interface AnalysisResult {
  score: number; // 0 to 100
  status: 'Faible' | 'Modéré' | 'Élevé';
  statusColor: 'emerald' | 'amber' | 'rose';
  executiveSummary: string;
  categories: {
    urgency: { score: number; label: string; details: string };
    brandImpersonation: { score: number; label: string; details: string };
    sensitiveData: { score: number; label: string; details: string };
    technical: { score: number; label: string; details: string };
  };
  alerts: DetectedAlert[];
  matchedKeywords: string[];
  advices: SecurityAdvice[];
  analyzedType: 'message' | 'url';
  inputSnippet: string;
  extractedUrls?: string[];
  timestamp: string;
}

// Base de connaissances des marques ciblées par le phishing
export const KNOWN_BRANDS: BrandTarget[] = [
  {
    name: 'PayPal',
    category: 'Paiement en ligne',
    officialDomains: ['paypal.com', 'paypal.fr'],
    keywords: ['paypal', 'pay-pal', 'service-paypal'],
  },
  {
    name: 'Impôts / DGFiP',
    category: 'Service Public',
    officialDomains: ['impots.gouv.fr', 'economie.gouv.fr'],
    keywords: ['impot', 'impots', 'dgfip', 'fisc', 'remboursement fiscal', 'declaration impots'],
  },
  {
    name: 'Ameli / Assurance Maladie',
    category: 'Santé publique',
    officialDomains: ['ameli.fr', 'assurance-maladie.fr'],
    keywords: ['ameli', 'carte vitale', 'assurance maladie', 'secu', 'securite sociale'],
  },
  {
    name: 'Orange',
    category: 'Télécoms',
    officialDomains: ['orange.fr', 'orange.com'],
    keywords: ['orange', 'espace client orange', 'facture orange', 'livebox'],
  },
  {
    name: 'La Poste / Colissimo / Chronopost',
    category: 'Livraison / Colis',
    officialDomains: ['laposte.fr', 'colissimo.fr', 'chronopost.fr'],
    keywords: ['laposte', 'colissimo', 'chronopost', 'colis', 'livraison', 'suivi de colis', 'frais de douane', 'affranchissement'],
  },
  {
    name: 'Amazon',
    category: 'E-commerce',
    officialDomains: ['amazon.fr', 'amazon.com'],
    keywords: ['amazon', 'commande amazon', 'prime'],
  },
  {
    name: 'Netflix',
    category: 'Streaming',
    officialDomains: ['netflix.com'],
    keywords: ['netflix', 'abonnement netflix', 'compte suspendu netflix'],
  },
  {
    name: 'Banque Postale / Crédit Agricole / BNP / SG / Caisse d’Épargne',
    category: 'Banque',
    officialDomains: ['labanquepostale.fr', 'credit-agricole.fr', 'bnpparibas.fr', 'societegenerale.fr', 'caisse-epargne.fr', 'boursorama.com'],
    keywords: ['banque', 'banque postale', 'credit agricole', 'bnp', 'societe generale', 'caisse epargne', 'boursorama', 'compte bancaire', 'virement', 'securipass', 'certicode'],
  },
  {
    name: 'Microsoft / Office 365',
    category: 'Logiciel / Cloud',
    officialDomains: ['microsoft.com', 'live.com', 'office.com', 'outlook.com'],
    keywords: ['microsoft', 'office 365', 'outlook', 'onedrive'],
  },
  {
    name: 'Apple / iCloud',
    category: 'Technologie',
    officialDomains: ['apple.com', 'icloud.com'],
    keywords: ['apple', 'icloud', 'apple id', 'itunes'],
  },
  {
    name: 'Mondial Relay / DHL / DPD',
    category: 'Transport & Logistique',
    officialDomains: ['mondialrelay.fr', 'dhl.com', 'dpd.com'],
    keywords: ['mondial relay', 'dhl', 'dpd', 'relais colis', 'taxe livraison'],
  },
  {
    name: 'ANTS / Permis / Carte Grise / Identité Numérique',
    category: 'Administration',
    officialDomains: ['ants.gouv.fr', 'interieur.gouv.fr', 'france-identite.gouv.fr'],
    keywords: ['ants', 'carte grise', 'permis de conduire', 'amende', 'stationnement', 'antai'],
  }
];

// Termes d'urgence et pression psychologique
const URGENCY_PATTERNS = [
  { regex: /\b(sous|dans les|d'ici)\s*(24|48|12|2|4|6)\s*(h|heures|hrs)\b/i, weight: 28, text: 'Délai d\'urgence strict (ex. 24h/48h)' },
  { regex: /\b(immédiatement|sans délai|action requise|urgent|de toute urgence|au plus vite)\b/i, weight: 25, text: 'Exigence d\'action immédiate' },
  { regex: /\b(compte suspendu|compte bloqué|blocage définitif|suspension définitive|clôture de votre compte)\b/i, weight: 32, text: 'Menace de suspension ou clôture de compte' },
  { regex: /\b(dernier avis|mise en demeure|poursuites? judiciaires?|huissier|tribunal|amende majorée)\b/i, weight: 30, text: 'Intimidation juridique ou sanctions' },
  { regex: /\b(activité suspecte|tentative de connexion|alerte de sécurité|appareil inconnu|piratage détecté)\b/i, weight: 24, text: 'Fausse alerte de sécurité ou intrusion' },
  { regex: /\b(remboursement en attente|crédit d'impôt|gain urgent|vous avez gagné|indemnité non réclamée|trop-perçu)\b/i, weight: 26, text: 'Appât financier / faux remboursement' },
  { regex: /\b(frais de douane|taxe de livraison|1[,.]99\s*(€|eur)|2[,.]99\s*(€|eur)|0[,.]99\s*(€|eur)|affranchissement insuffisant)\b/i, weight: 29, text: 'Micro-frais de déblocage colis (leurre classique)' },
  { regex: /\b(dernière chance|expire aujourd'hui|dernière relance|ultime rappel)\b/i, weight: 20, text: 'Formule de pression d\'expiration' },
];

// Termes de demandes sensibles
const SENSITIVE_DATA_PATTERNS = [
  { regex: /\b(mot de passe|password|code secret|code pin|code confidentiel|vos identifiants)\b/i, weight: 35, text: 'Demande directe de mot de passe ou code confidentiel' },
  { regex: /\b(carte bancaire|numéro de carte|cryptogramme|cvv|cvc|date d'expiration|iban|coordonnées bancaires)\b/i, weight: 38, text: 'Demande de carte bancaire ou coordonnées de paiement' },
  { regex: /\b(code sms|code de validation|code reçu par sms|code à (4|6) chiffres|code otp)\b/i, weight: 36, text: 'Demande de code d\'authentification SMS / OTP' },
  { regex: /\b(pièce d'identité|carte d'identité|passeport|justificatif de domicile|numéro de sécurité sociale)\b/i, weight: 30, text: 'Collecte de documents d\'identité personnels' },
  { regex: /\b(clique[zr] ici|cliquez sur le lien|suivez ce lien|connectez-vous|accéder à votre espace|régulariser votre situation|mettre à jour vos informations)\b/i, weight: 22, text: 'Incitation explicite au clic vers un portail externe' },
  { regex: /\b(vérifi(er|ez) votre identité|confirmer vos coordonnées|mise à jour obligatoire)\b/i, weight: 20, text: 'Demande de re-vérification d\'identité sous contrainte' }
];

// Domaines & TLD suspects
const SUSPICIOUS_TLDS = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.icu', '.work', '.click', '.monster', '.link', '.rest', '.cam', '.live', '.online', '.site'];
const URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 'is.gd', 't.co', 'ow.ly', 'cutt.ly', 'rb.gy', 'shorturl.at'];

// Calcul distance de Levenshtein simple
function levenshteinDistance(a: string, b: string): number {
  const matrix: number[][] = [];
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

// Extraction des URLs d'un texte
export function extractUrlsFromText(text: string): string[] {
  const urlRegex = /(https?:\/\/[^\s]+|www\.[^\s]+|[a-zA-Z0-9-]+\.(?:[a-zA-Z]{2,}|[a-zA-Z0-9-]+\.[a-zA-Z]{2,})(?:\/[^\s]*)?)/gi;
  const matches = text.match(urlRegex) || [];
  return Array.from(new Set(matches.map(u => u.replace(/[.,;:!?)]+$/, ''))));
}

// Extraction du nom de domaine
export function extractDomain(rawUrl: string): { hostname: string; protocol: string; pathname: string } {
  let cleaned = rawUrl.trim();
  if (!/^https?:\/\//i.test(cleaned)) {
    cleaned = 'https://' + cleaned;
  }
  try {
    const parsed = new URL(cleaned);
    return {
      hostname: parsed.hostname.toLowerCase(),
      protocol: parsed.protocol.replace(':', ''),
      pathname: parsed.pathname
    };
  } catch {
    const match = cleaned.replace(/^https?:\/\//i, '').split('/')[0];
    return {
      hostname: match ? match.toLowerCase() : cleaned.toLowerCase(),
      protocol: 'http',
      pathname: ''
    };
  }
}

// Analyse d'une URL
export function analyzeSingleUrl(urlInput: string, contextMessage?: string): {
  score: number;
  alerts: DetectedAlert[];
  technicalDetails: string[];
  isLegitimateDomain: boolean;
  targetBrand?: BrandTarget;
} {
  const alerts: DetectedAlert[] = [];
  const technicalDetails: string[] = [];
  let score = 0;

  const { hostname, protocol, pathname } = extractDomain(urlInput);

  // 1. Vérification si domaine officiel d'une marque réputée
  let isOfficial = false;
  for (const brand of KNOWN_BRANDS) {
    if (brand.officialDomains.some(od => hostname === od || hostname.endsWith('.' + od))) {
      isOfficial = true;
      alerts.push({
        id: `official-${brand.name}`,
        category: 'safe',
        severity: 'safe',
        title: `Domaine officiel vérifié : ${brand.name}`,
        description: `Le domaine « ${hostname} » correspond à l'infrastructure légitime et authentifiée de ${brand.name}.`,
        snippet: hostname
      });
      break;
    }
  }

  if (isOfficial) {
    return {
      score: 5,
      alerts,
      technicalDetails: ['Protocole vérifié', 'Domaine répertorié dans le registre de confiance'],
      isLegitimateDomain: true
    };
  }

  // 2. Protocole non sécurisé (HTTP au lieu de HTTPS)
  if (protocol === 'http') {
    score += 20;
    alerts.push({
      id: 'http-insecure',
      category: 'technical',
      severity: 'medium',
      title: 'Protocole non chiffré (HTTP)',
      description: 'L\'adresse n\'utilise pas de certificat TLS/HTTPS pour chiffrer les échanges.',
      snippet: 'http://'
    });
    technicalDetails.push('Absence de chiffrement HTTPS');
  }

  // 3. Adresse IP brute au lieu d'un nom de domaine
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  if (ipRegex.test(hostname)) {
    score += 45;
    alerts.push({
      id: 'raw-ip-host',
      category: 'technical',
      severity: 'high',
      title: 'Hôte par adresse IP directe',
      description: `L'URL pointe directement vers une adresse IP numérique (${hostname}) au lieu d'un nom de domaine enregistré, technique caractéristique des serveurs pirates non indexés.`,
      snippet: hostname
    });
    technicalDetails.push('Adresse IP numérique brute sans FQDN');
  }

  // 4. Raccourcisseur d'URL dissimulant la destination finale
  if (URL_SHORTENERS.some(s => hostname === s || hostname.endsWith('.' + s))) {
    score += 30;
    alerts.push({
      id: 'url-shortener',
      category: 'technical',
      severity: 'medium',
      title: 'Raccourcisseur d\'URL masquant la cible',
      description: `Le service « ${hostname} » dissimule la véritable destination du lien, empêchant l'utilisateur de vérifier l'expéditeur réel.`,
      snippet: hostname
    });
    technicalDetails.push('Raccourcisseur de lien public détecté');
  }

  // 5. TLD hautement suspect / gratuit
  const matchedTld = SUSPICIOUS_TLDS.find(tld => hostname.endsWith(tld));
  if (matchedTld) {
    score += 35;
    alerts.push({
      id: 'suspicious-tld',
      category: 'technical',
      severity: 'high',
      title: `Extension de domaine à fort risque (${matchedTld})`,
      description: `L'extension « ${matchedTld} » est statistiquement surreprésentée dans les campagnes de spam et de phishing en raison de son coût dérisoire ou de l'absence de vérification d'identité.`,
      snippet: matchedTld
    });
    technicalDetails.push(`TLD à risque cyber élevé : ${matchedTld}`);
  }

  // 6. Détection de Typosquatting / Combosquatting (Imitation de marque)
  let detectedImpersonation: BrandTarget | undefined;
  for (const brand of KNOWN_BRANDS) {
    // Vérifier si un mot-clé de marque figure dans le nom de domaine alors qu'il n'est PAS officiel
    const foundKw = brand.keywords.find(kw => {
      const sanitizedKw = kw.replace(/\s+/g, '');
      const sanitizedHost = hostname.replace(/\./g, '-');
      return sanitizedHost.includes(sanitizedKw) && sanitizedKw.length > 3;
    });

    if (foundKw) {
      detectedImpersonation = brand;
      score += 45;
      alerts.push({
        id: `typo-${brand.name}`,
        category: 'brand',
        severity: 'high',
        title: `Usurpation de marque détectée (${brand.name})`,
        description: `Le domaine « ${hostname} » utilise le nom de la marque « ${brand.name} » sans appartenir à ses domaines officiels (${brand.officialDomains.join(', ')}). C'est un cas typique de combosquatting visant à tromper l'internaute.`,
        snippet: hostname
      });
      technicalDetails.push(`Combosquatting ciblant ${brand.name}`);
      break;
    }

    // Vérifier une distance de Levenshtein proche avec le nom de marque
    for (const od of brand.officialDomains) {
      const baseOd = od.split('.')[0];
      const hostParts = hostname.split('.');
      const mainHost = hostParts.length > 1 ? hostParts[hostParts.length - 2] : hostParts[0];
      if (mainHost !== baseOd && Math.abs(mainHost.length - baseOd.length) <= 2) {
        const dist = levenshteinDistance(mainHost, baseOd);
        if (dist === 1 || (dist === 2 && baseOd.length >= 6)) {
          detectedImpersonation = brand;
          score += 40;
          alerts.push({
            id: `levenshtein-${brand.name}`,
            category: 'brand',
            severity: 'high',
            title: `Typosquatting par substitution de caractères (${brand.name})`,
            description: `Le domaine « ${mainHost} » présente une similitude graphique trompeuse avec le domaine officiel « ${baseOd} » de ${brand.name} (distance typo = ${dist}).`,
            snippet: hostname
          });
          technicalDetails.push(`Typosquatting graphique (altération de ${baseOd})`);
          break;
        }
      }
    }
  }

  // 7. Mots-clés suspects dans le sous-domaine ou le chemin (ex: login, secure, verification, compte, update)
  const suspiciousKeywords = ['login', 'signin', 'verification', 'verify', 'securite', 'securise', 'auth', 'update', 'portail', 'compte', 'facture', 'paiement', 'validation', 'client'];
  const foundSecKeywords = suspiciousKeywords.filter(kw => hostname.includes(kw) || pathname.includes(kw));
  if (foundSecKeywords.length > 0) {
    score += 15 * Math.min(foundSecKeywords.length, 2);
    alerts.push({
      id: 'deceptive-keywords',
      category: 'technical',
      severity: 'medium',
      title: 'Termes leurres de sécurité ou d\'authentification',
      description: `L'URL intègre des termes trompeurs (${foundSecKeywords.map(k => `« ${k} »`).join(', ')}) conçus pour simuler un espace d'authentification officiel.`,
      snippet: foundSecKeywords.join(', ')
    });
    technicalDetails.push(`Mots-clés leurres : ${foundSecKeywords.join(', ')}`);
  }

  // 8. Sous-domaines excessifs (ex: paypal.com.securite-login.xyz)
  const dotCount = (hostname.match(/\./g) || []).length;
  if (dotCount >= 3) {
    score += 20;
    alerts.push({
      id: 'deep-subdomain',
      category: 'technical',
      severity: 'medium',
      title: 'Structure de sous-domaines abusive',
      description: `L'adresse utilise ${dotCount} sous-niveaux de domaine pour dissimuler le véritable domaine racine.`,
      snippet: hostname
    });
    technicalDetails.push(`Arborescence DNS suspecte (${dotCount} séparateurs)`);
  }

  return {
    score: Math.min(score, 100),
    alerts,
    technicalDetails,
    isLegitimateDomain: false,
    targetBrand: detectedImpersonation
  };
}

// Fonction Principale : Analyse complète de Message ou URL
export function analyzeInput(rawInput: string, mode: 'message' | 'url'): AnalysisResult {
  const input = rawInput.trim();
  const alerts: DetectedAlert[] = [];
  const matchedKeywords: string[] = [];
  let urgencyScore = 0;
  let sensitiveScore = 0;
  let brandScore = 0;
  let technicalScore = 0;

  // Si l'entrée est vide
  if (!input) {
    return {
      score: 0,
      status: 'Faible',
      statusColor: 'emerald',
      executiveSummary: 'Aucun contenu fourni pour analyse.',
      categories: {
        urgency: { score: 0, label: 'Nul', details: 'Aucun contenu analysé' },
        brandImpersonation: { score: 0, label: 'Nul', details: 'Aucun contenu analysé' },
        sensitiveData: { score: 0, label: 'Nul', details: 'Aucun contenu analysé' },
        technical: { score: 0, label: 'Nul', details: 'Aucun contenu analysé' },
      },
      alerts: [],
      matchedKeywords: [],
      advices: [
        { icon: 'shield-alert', text: 'Entrez un texte d\'e-mail, un SMS ou une URL pour démarrer l\'évaluation.' }
      ],
      analyzedType: mode,
      inputSnippet: '',
      timestamp: new Date().toLocaleTimeString('fr-FR')
    };
  }

  // --- ANALYSE SELON LE MODE ---
  const extractedUrls = mode === 'message' ? extractUrlsFromText(input) : [input];

  // 1. Analyse des URLs présentes
  let urlAnalysisResults: ReturnType<typeof analyzeSingleUrl>[] = [];
  if (extractedUrls.length > 0) {
    urlAnalysisResults = extractedUrls.map(u => analyzeSingleUrl(u, input));
    for (const urlRes of urlAnalysisResults) {
      alerts.push(...urlRes.alerts);
      technicalScore = Math.max(technicalScore, urlRes.score);
      if (urlRes.targetBrand) {
        brandScore = Math.max(brandScore, 45);
      }
    }
  }

  // 2. Détection de la fausse urgence et manipulation psychologique
  let detectedUrgencyTerms: string[] = [];
  for (const pattern of URGENCY_PATTERNS) {
    if (pattern.regex.test(input)) {
      urgencyScore += pattern.weight;
      detectedUrgencyTerms.push(pattern.text);
      matchedKeywords.push(pattern.text);
    }
  }

  if (detectedUrgencyTerms.length > 0) {
    alerts.push({
      id: 'urgency-detected',
      category: 'urgency',
      severity: urgencyScore >= 40 ? 'high' : 'medium',
      title: 'Pression psychologique & Fausse urgence',
      description: `Le message exploite des leviers de panique émotionnelle : ${detectedUrgencyTerms.join(', ')}. L'objectif des attaquants est de vous faire agir dans la précipitation sans vérifier la légitimité.`,
      snippet: detectedUrgencyTerms.join(' • ')
    });
  }

  // 3. Détection des demandes de données sensibles
  let detectedSensitiveTerms: string[] = [];
  for (const pattern of SENSITIVE_DATA_PATTERNS) {
    if (pattern.regex.test(input)) {
      sensitiveScore += pattern.weight;
      detectedSensitiveTerms.push(pattern.text);
      matchedKeywords.push(pattern.text);
    }
  }

  if (detectedSensitiveTerms.length > 0) {
    alerts.push({
      id: 'sensitive-data-detected',
      category: 'sensitive_data',
      severity: sensitiveScore >= 35 ? 'high' : 'medium',
      title: 'Sollicitation de données confidentielles',
      description: `Le message tente de collecter des informations critiques : ${detectedSensitiveTerms.join(', ')}. Aucun organisme légitime ne sollicite ce type d'information par messagerie non sécurisée.`,
      snippet: detectedSensitiveTerms.join(' • ')
    });
  }

  // 4. Imitation de Marque dans le texte du message
  if (mode === 'message') {
    for (const brand of KNOWN_BRANDS) {
      const brandMentioned = brand.keywords.some(kw => new RegExp(`\\b${kw}\\b`, 'i').test(input));
      if (brandMentioned) {
        // Si la marque est mentionnée dans le texte, vérifions si des URLs sont présentes
        if (extractedUrls.length > 0) {
          const hasOfficialDomain = extractedUrls.some(u => {
            const { hostname } = extractDomain(u);
            return brand.officialDomains.some(od => hostname === od || hostname.endsWith('.' + od));
          });

          if (!hasOfficialDomain) {
            brandScore += 45;
            alerts.push({
              id: `brand-mismatch-${brand.name}`,
              category: 'brand',
              severity: 'high',
              title: `Discordance d'identité de marque (${brand.name})`,
              description: `Le texte se réclame de « ${brand.name} », mais les liens contenus ne redirigent aucunement vers les domaines officiels reconnus (${brand.officialDomains.join(', ')}).`,
              snippet: `${brand.name} vs ${extractedUrls.join(', ')}`
            });
            matchedKeywords.push(`Usurpation ${brand.name}`);
            break;
          }
        }
      }
    }
  }

  // Normalisation des sous-scores
  urgencyScore = Math.min(urgencyScore, 100);
  sensitiveScore = Math.min(sensitiveScore, 100);
  brandScore = Math.min(brandScore, 100);
  technicalScore = Math.min(technicalScore, 100);

  // Calcul du score global pondéré
  let totalScore = 0;
  if (mode === 'url') {
    // En mode URL pure, le score technique et typosquatting domine
    totalScore = Math.round(technicalScore * 0.7 + brandScore * 0.3);
  } else {
    // En mode message, combinaison des 4 piliers cyber
    const maxSubScore = Math.max(urgencyScore, sensitiveScore, brandScore, technicalScore);
    const avgSubScore = (urgencyScore + sensitiveScore + brandScore + technicalScore) / 4;
    // Si un indicateur critique est à fond, le risque global doit être élevé
    totalScore = Math.round(maxSubScore * 0.65 + avgSubScore * 0.35);
  }

  // Ajustement pour cas 100% légitimes
  const hasOnlySafe = alerts.length > 0 && alerts.every(a => a.severity === 'safe');
  if (hasOnlySafe) {
    totalScore = Math.min(totalScore, 10);
  }

  // Cap 0 à 100
  totalScore = Math.max(0, Math.min(100, totalScore));

  // Attribution du Statut
  let status: 'Faible' | 'Modéré' | 'Élevé' = 'Faible';
  let statusColor: 'emerald' | 'amber' | 'rose' = 'emerald';

  if (totalScore >= 70) {
    status = 'Élevé';
    statusColor = 'rose';
  } else if (totalScore >= 31) {
    status = 'Modéré';
    statusColor = 'amber';
  } else {
    status = 'Faible';
    statusColor = 'emerald';
  }

  // Synthèse Pédagogique fluide et accessible pour tout public
  let executiveSummary = '';
  if (status === 'Élevé') {
    executiveSummary = `DANGER IMMÉDIAT : Cette analyse révèle de multiples signaux caractéristiques d'une tentative de fraude en ligne (phishing/escroquerie). L'expéditeur cherche à usurper l'identité d'un organisme de confiance pour vous dérober vos identifiants ou coordonnées bancaires. Ne donnez aucune suite.`;
  } else if (status === 'Modéré') {
    executiveSummary = `VIGILANCE REQUISE : Des anomalies ou des tournures de phrases insistantes ont été relevées. Sans constituer une attaque certaine, plusieurs indicateurs justifient une vérification prudente avant d'interagir ou de saisir la moindre information.`;
  } else {
    executiveSummary = `AUCUNE MENACE MAJEURE DÉTECTÉE : Le contenu analysé ne présente pas les indicateurs habituels d'hameçonnage (pas de pression d'urgence, pas de demande illégitime de données bancaires, domaines officiels ou cohérents). Restez néanmoins attentif.`;
  }

  // Conseils Pratiques adaptés au cas détecté
  const advices: SecurityAdvice[] = [];
  if (status === 'Élevé') {
    advices.push(
      { icon: 'shield-alert', text: 'Ne cliquez sur aucun lien et ne téléchargez aucune pièce jointe.', urgent: true },
      { icon: 'lock', text: 'Ne saisissez jamais votre mot de passe, code SMS ou numéro de carte bancaire.', urgent: true },
      { icon: 'external-link', text: 'Vérifiez directement votre compte en tapant vous-même l\'adresse officielle dans votre navigateur.' },
      { icon: 'trash', text: 'Supprimez immédiatement ce message ou fermez cette page Web.' },
      { icon: 'flag', text: 'Signalez cette menace sur la plateforme officielle (Phishing Initiative ou Signal-Spam).' }
    );
  } else if (status === 'Modéré') {
    advices.push(
      { icon: 'external-link', text: 'Ne passez pas par le lien fourni : connectez-vous via l\'application officielle ou vos favoris.' },
      { icon: 'lock', text: 'Vérifiez scrupuleusement l\'expéditeur réel de l\'e-mail (après le symbole @).' },
      { icon: 'shield-alert', text: 'En cas de doute, contactez l\'organisme par son numéro de téléphone officiel.' }
    );
  } else {
    advices.push(
      { icon: 'check', text: 'Le message semble légitime, mais conservez toujours le réflexe de vérifier l\'URL avant toute authentification.' },
      { icon: 'lock', text: 'Activez l\'authentification à double facteur (2FA) sur tous vos comptes sensibles.' }
    );
  }

  return {
    score: totalScore,
    status,
    statusColor,
    executiveSummary,
    categories: {
      urgency: {
        score: urgencyScore,
        label: urgencyScore >= 50 ? 'Élevée' : urgencyScore >= 20 ? 'Moyenne' : 'Basse',
        details: detectedUrgencyTerms.length > 0 ? detectedUrgencyTerms.slice(0, 2).join(', ') : 'Aucune contrainte de temps excessive'
      },
      brandImpersonation: {
        score: brandScore,
        label: brandScore >= 50 ? 'Forte suspicion' : brandScore >= 20 ? 'Doute' : 'Aucune',
        details: brandScore > 0 ? 'Divergence entre expéditeur revendiqué et domaine réel' : 'Aucune usurpation de marque détectée'
      },
      sensitiveData: {
        score: sensitiveScore,
        label: sensitiveScore >= 50 ? 'Critique' : sensitiveScore >= 20 ? 'Suspecte' : 'Nulle',
        details: detectedSensitiveTerms.length > 0 ? detectedSensitiveTerms.slice(0, 2).join(', ') : 'Pas de demande d\'identifiant ou carte bancaire'
      },
      technical: {
        score: technicalScore,
        label: technicalScore >= 50 ? 'Anomalies graves' : technicalScore >= 20 ? 'Vigilance' : 'Normal',
        details: extractedUrls.length > 0 ? `${extractedUrls.length} adresse(s) examinée(s)` : 'Pas d\'URL suspecte'
      }
    },
    alerts,
    matchedKeywords,
    advices,
    analyzedType: mode,
    inputSnippet: input.length > 120 ? input.substring(0, 120) + '...' : input,
    extractedUrls: extractedUrls.length > 0 ? extractedUrls : undefined,
    timestamp: new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  };
}

// Exemples prédéfinis prêts à tester
export const PRESET_EXAMPLES = [
  {
    id: 'sms-chronopost',
    title: 'SMS Livraison Colis Suspect',
    category: 'SMS Phishing (Smishing)',
    mode: 'message' as const,
    risk: 'danger',
    text: `Chronopost Info : Votre colis n°FR-892401 est bloqué en douane en raison d'un affranchissement insuffisant (frais de 1.99 EUR requis sous 24h). Veuillez régulariser immédiatement votre situation pour éviter le retour à l'expéditeur : https://chronopost-suivi-douane.xyz/paiement`
  },
  {
    id: 'email-paypal-fake',
    title: 'Faux E-mail Alerte Sécurité PayPal',
    category: 'E-mail Phishing',
    mode: 'message' as const,
    risk: 'danger',
    text: `Alerte de sécurité PayPal : Une tentative de connexion inhabituelle a été détectée sur votre compte. Votre compte sera suspendu définitivement dans 24 heures sans action de votre part. Cliquez ici pour vérifier votre identité et confirmer vos coordonnées bancaires et mot de passe : https://paypal-verification-client.com/login`
  },
  {
    id: 'url-impots-typo',
    title: 'URL Faux Site Impôts / DGFiP',
    category: 'URL Typosquatting',
    mode: 'url' as const,
    risk: 'danger',
    text: `http://service-impots-remboursement-update.net/formulaire-bancaire`
  },
  {
    id: 'sms-ameli',
    title: 'SMS Carte Vitale / Remboursement Ameli',
    category: 'SMS Phishing',
    mode: 'message' as const,
    risk: 'danger',
    text: `Assurance Maladie : Votre nouvelle Carte Vitale V3 est disponible. Un remboursement en attente de 312,50€ ne peut être versé. Remplissez vos coordonnées avant clôture sous 48h sur : http://ameli-carte-vitale-renouvellement.top`
  },
  {
    id: 'email-legit',
    title: 'E-mail Professionnel Légitime',
    category: 'Légitime (Sûr)',
    mode: 'message' as const,
    risk: 'safe',
    text: `Bonjour Marc, merci pour l'envoi du compte-rendu de la réunion d'hier. Pourrais-tu m'envoyer la version finale des diapositives d'ici vendredi prochain pour que nous puissions finaliser la présentation du projet ? Cordialement, Thomas.`
  },
  {
    id: 'url-legit-impots',
    title: 'URL Officielle DGFiP (impots.gouv.fr)',
    category: 'Légitime (Sûr)',
    mode: 'url' as const,
    risk: 'safe',
    text: `https://www.impots.gouv.fr/particulier`
  }
];
