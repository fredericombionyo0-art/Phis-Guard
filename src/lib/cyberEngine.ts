import { AnalysisResult, AnalysisType, IndicatorSeverity, RiskLevel, ThreatIndicator, DomainDecomposition } from '../types/cyber';

// Base de connaissances des marques ciblées et leurs domaines légitimes officiels
export interface BrandDefinition {
  name: string;
  aliases: string[];
  officialDomains: string[];
  category: 'banque' | 'administration' | 'livraison' | 'telecom' | 'tech' | 'autre';
}

export const KNOWN_BRANDS: BrandDefinition[] = [
  {
    name: 'PayPal',
    aliases: ['paypal', 'pay-pal'],
    officialDomains: ['paypal.com', 'paypal.fr', 'paypal-communication.com'],
    category: 'banque',
  },
  {
    name: 'Ameli / Assurance Maladie',
    aliases: ['ameli', 'assurance maladie', 'carte vitale', 'secu', 'sécurité sociale', 'cpam'],
    officialDomains: ['ameli.fr', 'assurance-maladie.fr'],
    category: 'administration',
  },
  {
    name: 'Impôts / DGFiP',
    aliases: ['impots', 'impôts', 'dgfip', 'direction generale des finances publiques', 'avis d imposition', 'remboursement impot'],
    officialDomains: ['impots.gouv.fr', 'economie.gouv.fr'],
    category: 'administration',
  },
  {
    name: 'Orange',
    aliases: ['orange', 'sosh'],
    officialDomains: ['orange.fr', 'orange.com', 'sosh.fr'],
    category: 'telecom',
  },
  {
    name: 'SFR',
    aliases: ['sfr', 'red by sfr'],
    officialDomains: ['sfr.fr', 'red-by-sfr.fr'],
    category: 'telecom',
  },
  {
    name: 'Crédit Agricole',
    aliases: ['credit agricole', 'crédit agricole', 'ca-enligne'],
    officialDomains: ['credit-agricole.fr', 'ca-paris.fr'],
    category: 'banque',
  },
  {
    name: 'BNP Paribas',
    aliases: ['bnp paribas', 'bnp', 'mabanque'],
    officialDomains: ['mabanque.bnpparibas', 'bnpparibas.com', 'bnpparibas.fr'],
    category: 'banque',
  },
  {
    name: 'Société Générale',
    aliases: ['societe generale', 'société générale', 'sg'],
    officialDomains: ['societegenerale.fr', 'particuliers.societegenerale.fr'],
    category: 'banque',
  },
  {
    name: 'La Banque Postale',
    aliases: ['banque postale', 'la banque postale'],
    officialDomains: ['labanquepostale.fr'],
    category: 'banque',
  },
  {
    name: 'La Poste / Chronopost',
    aliases: ['chronopost', 'la poste', 'laposte', 'colissimo', 'dpd'],
    officialDomains: ['laposte.fr', 'chronopost.fr', 'colissimo.fr', 'dpd.fr'],
    category: 'livraison',
  },
  {
    name: 'DHL / UPS / Mondial Relay',
    aliases: ['dhl', 'ups', 'mondial relay', 'fedex'],
    officialDomains: ['dhl.com', 'ups.com', 'mondialrelay.fr', 'fedex.com'],
    category: 'livraison',
  },
  {
    name: 'Netflix',
    aliases: ['netflix'],
    officialDomains: ['netflix.com'],
    category: 'tech',
  },
  {
    name: 'Amazon',
    aliases: ['amazon', 'prime video'],
    officialDomains: ['amazon.fr', 'amazon.com', 'primevideo.com'],
    category: 'tech',
  },
  {
    name: 'Apple',
    aliases: ['apple', 'icloud', 'itunes', 'apple id'],
    officialDomains: ['apple.com', 'icloud.com'],
    category: 'tech',
  },
  {
    name: 'Microsoft',
    aliases: ['microsoft', 'outlook', 'office 365', 'hotmail', 'onedrive'],
    officialDomains: ['microsoft.com', 'live.com', 'office.com', 'outlook.com'],
    category: 'tech',
  },
  {
    name: 'ANTAI (Amendes)',
    aliases: ['antai', 'contravention', 'amende', 'radars', 'infraction routiere'],
    officialDomains: ['antai.gouv.fr', 'amendes.gouv.fr'],
    category: 'administration',
  },
  {
    name: 'CAF',
    aliases: ['caf', 'caisse d allocations familiales'],
    officialDomains: ['caf.fr'],
    category: 'administration',
  },
];

// TLDs considérés à haut risque ou atypiques pour des services institutionnels
const SUSPICIOUS_TLDS = [
  'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'club', 'work',
  'icu', 'cam', 'rest', 'vip', 'fit', 'monster', 'cyou', 'sbs', 'click',
  'stream', 'bid', 'country', 'kim', 'casa', 'loan', 'racing', 'date'
];

// Raccourcisseurs d'URL populaires fréquemment détournés
const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 'is.gd', 'cutt.ly', 'rb.gy', 't.co', 'ow.ly',
  'buff.ly', 'rebrand.ly', 'shorturl.at', 'clck.ru'
];

// Motifs d'urgence, panique et pression psychologique
const URGENCY_PATTERNS = [
  { regex: /(suspendu|bloqu[ée]|interdit|cl[ôo]tur[ée]|résili[ée])\s+(sous|dans|d['’]ici)\s+(\d+\s*(h|heures?|jours?)|24h|48h|72h)/i, label: "Menace de suspension de compte avec ultimatum temporel", weight: 30 },
  { regex: /(action|intervention|vérification|confirmation)\s+(immédiate|urgente|requise|obligatoire|indispensable)/i, label: "Action immédiate ou urgente exigée", weight: 25 },
  { regex: /(dernier\s+avis|ultime\s+rappel|mise\s+en\s+demeure|huissier|poursuites?\s+judiciaires?|tribunal|amende\s+majorée)/i, label: "Menace judiciaire, huissier ou majoration d'amende", weight: 35 },
  { regex: /(compte\s+suspendu|accès\s+restreint|activité\s+suspecte|tentative\s+de\s+connexion\s+non\s+autorisée)/i, label: "Fausse alerte de sécurité ou activité inhabituelle", weight: 25 },
  { regex: /(frais\s+de\s+douane|colis\s+retenu|colis\s+en\s+attente|adresse\s+incomplète|frais\s+de\s+port\s+impayés?)/i, label: "Fausse alerte de colis bloqué ou frais de douane", weight: 25 },
  { regex: /(gain\s+urgent|tirage\s+au\s+sort|vous\s+avez\s+gagné|remboursement\s+de\s+\d+|crédit\s+de\s+\d+\s*€)/i, label: "Appât du gain ou promesse de remboursement urgent", weight: 25 },
  { regex: /(dans\s+les\s+plus\s+brefs\s+délais|sans\s+tarder|immédiatement|avant\s+ce\s+soir|expire\s+bientôt)/i, label: "Pression temporelle invitant à agir précipitamment", weight: 20 },
  { regex: /(votre\s+carte\s+vitale\s+v3|renouveler\s+votre\s+carte\s+vitale)/i, label: "Arnaque récurrente à la fausse carte vitale", weight: 35 }
];

// Motifs de collecte de données confidentielles
const SENSITIVE_DATA_PATTERNS = [
  { regex: /(mot\s+de\s+passe|password|code\s+secret|code\s+pin)/i, label: "Demande explicite de mot de passe ou code confidentiel", weight: 35 },
  { regex: /(numéro\s+de\s+carte|carte\s+bancaire|numéro\s+cb|cryptogramme|cvv|cvc|date\s+d['’]expiration)/i, label: "Demande d'informations bancaires (carte, CVV)", weight: 45 },
  { regex: /(code\s+reçu\s+par\s+sms|code\s+de\s+validation|code\s+2fa|passcode|code\s+de\s+sécurité)/i, label: "Tentative d'interception d'un code de sécurité SMS / 2FA", weight: 40 },
  { regex: /(pièce\s+d['’]identité|carte\s+nationale\s+d['’]identité|passeport|permis\s+de\s+conduire|justificatif)/i, label: "Demande de copie de pièce d'identité (usurpation d'identité)", weight: 35 },
  { regex: /(rib|iban|bic|coordonnées\s+bancaires)/i, label: "Demande de coordonnées bancaires ou RIB", weight: 35 },
  { regex: /(cliquez\s+ici\s+pour\s+(vous\s+connecter|valider|mettre\s+à\s+jour|confirmer|payer))/i, label: "Incitation directe au clic vers une page de connexion", weight: 20 },
  { regex: /(mettre\s+à\s+jour\s+vos\s+coordonnées|actualiser\s+vos\s+informations\s+personnelles)/i, label: "Demande de mise à jour des coordonnées personnelles", weight: 25 },
];

/**
 * Décompose et inspecte une URL pour en extraire l'anatomie cyber
 */
export function decomposeUrl(input: string): DomainDecomposition | null {
  let cleaned = input.trim();
  if (!cleaned) return null;

  // Si l'utilisateur n'a pas tapé de protocole, ajouter temporairement https:// pour parser
  let hasProtocol = /^https?:\/\//i.test(cleaned);
  let urlToParse = hasProtocol ? cleaned : `https://${cleaned}`;

  try {
    const parsed = new URL(urlToParse);
    const hostname = parsed.hostname.toLowerCase();
    const protocol = parsed.protocol.replace(':', '');
    const path = parsed.pathname + parsed.search + parsed.hash;

    // Détection adresse IP
    const isIpAddress = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || /^\[?[a-f0-9:]+\]?$/i.test(hostname);

    // Extraction du TLD et sous-domaines
    const parts = hostname.split('.');
    let tld = '';
    let rootDomain = hostname;
    let subdomain = '';

    if (!isIpAddress && parts.length >= 2) {
      tld = parts[parts.length - 1];
      // Gestion des TLD composés type .gouv.fr, .co.uk
      if (parts.length >= 3 && (parts[parts.length - 2] === 'gouv' || parts[parts.length - 2] === 'co' || parts[parts.length - 2] === 'asso')) {
        tld = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
        rootDomain = `${parts[parts.length - 3]}.${tld}`;
        subdomain = parts.slice(0, parts.length - 3).join('.');
      } else {
        rootDomain = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
        subdomain = parts.slice(0, parts.length - 2).join('.');
      }
    }

    const isShortener = URL_SHORTENERS.includes(hostname) || URL_SHORTENERS.some(s => hostname.endsWith(`.${s}`));
    const isSuspiciousTld = SUSPICIOUS_TLDS.includes(tld.toLowerCase());
    const hasPunycode = hostname.startsWith('xn--') || hostname.includes('.xn--');
    const hasUserInfoAt = parsed.username !== '' || parsed.password !== '' || cleaned.includes('@');

    // Détection d'une marque ciblée
    let targetedBrand: string | undefined = undefined;
    for (const brand of KNOWN_BRANDS) {
      const matchBrand = brand.aliases.some(alias => {
        const cleanAlias = alias.replace(/[^a-z0-9]/gi, '');
        return hostname.replace(/[^a-z0-9]/gi, '').includes(cleanAlias);
      });
      if (matchBrand) {
        targetedBrand = brand.name;
        break;
      }
    }

    return {
      originalUrl: input,
      hostname,
      protocol,
      tld,
      subdomain,
      rootDomain,
      path,
      targetedBrand,
      isIpAddress,
      isShortener,
      isSuspiciousTld,
      hasPunycode,
      hasUserInfoAt
    };
  } catch {
    return null;
  }
}

/**
 * Moteur d'analyse d'une URL
 */
export function analyzeUrlThreat(rawUrl: string): AnalysisResult {
  const decomp = decomposeUrl(rawUrl);
  const indicators: ThreatIndicator[] = [];
  let score = 0;
  const fullInput = rawUrl.trim();
  const inputSnippet = fullInput.length > 80 ? `${fullInput.substring(0, 77)}...` : fullInput;

  if (!decomp) {
    return {
      id: `analysis-${Date.now()}`,
      timestamp: Date.now(),
      type: 'url',
      inputSnippet,
      fullInput,
      score: 65,
      level: 'moderate',
      verdict: 'Format d’URL Invalide ou Déguisé',
      summary: 'L’adresse fournie ne respecte pas les normes standards du Web ou contient des caractères interdits, une technique fréquemment utilisée pour contourner les filtres de sécurité.',
      indicators: [{
        id: 'err-invalid-format',
        category: 'obfuscation',
        severity: 'warning',
        title: 'Format d\'adresse suspect',
        description: 'La chaîne saisie ne constitue pas une URL canonique valide.',
        points: 40
      }],
      recommendations: [
        'Ne tentez pas d’ouvrir cette adresse dans un navigateur.',
        'Les liens mal formés dissimulent souvent des injections de scripts ou des redirections masquées.'
      ],
      urgencyDetected: false,
      brandImpersonationDetected: false,
      sensitiveDataDetected: false
    };
  }

  // 1. Détection de marque et Usurpation (Typosquatting / Combosquatting)
  let brandMatched: BrandDefinition | null = null;
  for (const b of KNOWN_BRANDS) {
    const found = b.aliases.some(alias => {
      const regex = new RegExp(`(^|[-._])${alias.replace(/[^a-z0-9]/gi, '')}([-._]|$)`, 'i');
      return regex.test(decomp.hostname) || decomp.hostname.includes(alias.replace(/\s+/g, ''));
    });
    if (found) {
      brandMatched = b;
      break;
    }
  }

  let brandImpersonationDetected = false;

  if (brandMatched) {
    const isLegitimate = brandMatched.officialDomains.some(off => 
      decomp.hostname === off || decomp.hostname.endsWith(`.${off}`)
    );

    if (isLegitimate) {
      indicators.push({
        id: 'brand-official-domain',
        category: 'typosquatting',
        severity: 'info',
        title: `Domaine officiel vérifié : ${brandMatched.name}`,
        description: `Le domaine ${decomp.hostname} correspond à un domaine officiellement certifié pour ${brandMatched.name}.`,
        points: -25,
        evidence: decomp.hostname
      });
    } else {
      brandImpersonationDetected = true;
      score += 45;
      indicators.push({
        id: 'brand-typosquatting',
        category: 'typosquatting',
        severity: 'critical',
        title: `Imitation de marque détectée (${brandMatched.name})`,
        description: `Le nom de domaine utilise la marque « ${brandMatched.name} » ou une variante (${decomp.hostname}), mais ne fait pas partie des domaines officiels connus (${brandMatched.officialDomains.join(', ')}). Il s'agit d'une tentative classique de combosquatting ou d'usurpation.`,
        points: 45,
        evidence: `Domaine frauduleux : ${decomp.hostname}`
      });
    }
  }

  // 2. Présence de tirets multiples ou sous-domaines trompeurs
  const hyphenCount = (decomp.hostname.match(/-/g) || []).length;
  if (hyphenCount >= 2 && !indicators.some(i => i.id === 'brand-official-domain')) {
    score += 20;
    indicators.push({
      id: 'excessive-hyphens',
      category: 'suspicious_domain',
      severity: 'warning',
      title: 'Multiples tirets dans le nom de domaine',
      description: `Le domaine comporte ${hyphenCount} tirets, une technique courante (ex: paypal-verification-compte.com) visant à duper l'internaute en imitant un service réel.`,
      points: 20,
      evidence: decomp.hostname
    });
  }

  // 3. Mots-clés suspects dans l'URL ou sous-domaine
  const securityKeywords = ['securite', 'security', 'verification', 'update', 'login', 'connexion', 'paiement', 'facture', 'compte', 'auth', 'valider', 'renouveler', 'remboursement'];
  const matchedSecurityKw = securityKeywords.filter(kw => decomp.hostname.includes(kw) || decomp.path.toLowerCase().includes(kw));
  if (matchedSecurityKw.length > 0 && !indicators.some(i => i.id === 'brand-official-domain')) {
    score += 15;
    indicators.push({
      id: 'deceptive-keywords',
      category: 'suspicious_domain',
      severity: 'warning',
      title: 'Mots-clés de réassurance ou d\'authentification dans l\'URL',
      description: `L'URL contient des termes incitatifs : [${matchedSecurityKw.join(', ')}] souvent utilisés pour créer un faux sentiment de sécurité.`,
      points: 15,
      evidence: matchedSecurityKw.join(', ')
    });
  }

  // 4. Adresse IP brute au lieu d'un nom de domaine
  if (decomp.isIpAddress) {
    score += 35;
    indicators.push({
      id: 'ip-address-host',
      category: 'obfuscation',
      severity: 'critical',
      title: 'Hébergement direct sur adresse IP numérique',
      description: `L'adresse utilise une adresse IP directe (${decomp.hostname}) sans nom de domaine déposé. C'est une signature fréquente de serveurs pirates éphémères.`,
      points: 35,
      evidence: decomp.hostname
    });
  }

  // 5. Raccourcisseur d'URL masquant la destination
  if (decomp.isShortener) {
    score += 25;
    indicators.push({
      id: 'url-shortener',
      category: 'obfuscation',
      severity: 'warning',
      title: 'Utilisation d\'un réducteur de lien masquant la cible',
      description: `Le service « ${decomp.hostname} » masque la destination finale réelle du site. Les attaquants s'en servent pour contourner les scanners d'e-mails et de SMS.`,
      points: 25,
      evidence: decomp.hostname
    });
  }

  // 6. Extension TLD à haut risque
  if (decomp.isSuspiciousTld) {
    score += 25;
    indicators.push({
      id: 'suspicious-tld',
      category: 'suspicious_domain',
      severity: 'warning',
      title: `Extension de domaine à haut risque (.${decomp.tld})`,
      description: `L'extension .${decomp.tld} fait partie des TLD gratuits ou à très bas coût souvent exploités pour des campagnes de spam et de phishing massif.`,
      points: 25,
      evidence: `.${decomp.tld}`
    });
  }

  // 7. Masquage via le symbole @ (UserInfo)
  if (decomp.hasUserInfoAt) {
    score += 40;
    indicators.push({
      id: 'at-symbol-trick',
      category: 'obfuscation',
      severity: 'critical',
      title: 'Technique d\'obfuscation par le symbole « @ »',
      description: 'L’URL utilise le symbole « @ », ce qui fait que le navigateur ignore tout ce qui précède pour se connecter uniquement au serveur situé après le @.',
      points: 40,
      evidence: decomp.originalUrl
    });
  }

  // 8. Punycode / Homoglyphes
  if (decomp.hasPunycode) {
    score += 30;
    indicators.push({
      id: 'punycode-homoglyph',
      category: 'typosquatting',
      severity: 'critical',
      title: 'Caractères internationaux / Punycode (Attaque par homoglyphe)',
      description: 'Le nom de domaine utilise un encodage Punycode (xn--), ce qui permet d\'imiter visuellement des lettres latines avec des alphabets cyrilliques ou grecs pour tromper l\'œil humain.',
      points: 30,
      evidence: decomp.hostname
    });
  }

  // 9. Protocole HTTP non chiffré
  if (decomp.protocol === 'http' && !decomp.isShortener) {
    score += 15;
    indicators.push({
      id: 'no-https',
      category: 'suspicious_domain',
      severity: 'warning',
      title: 'Protocole non sécurisé (HTTP simple)',
      description: 'Le site n\'utilise pas de chiffrement HTTPS. Les identifiants ou informations transmises circulent en clair sur le réseau.',
      points: 15,
      evidence: 'http://'
    });
  }

  // Normalisation du score entre 0 et 100
  const finalScore = Math.max(0, Math.min(100, score));

  // Attribution du niveau de risque
  let level: RiskLevel = 'low';
  let verdict = 'Domaine Légitime ou Risque Faible';
  let summary = 'Cette adresse ne présente aucun des signaux d’alerte majeurs de phishing ou d’usurpation connus.';

  if (finalScore >= 70) {
    level = 'high';
    verdict = 'DANGER CRITIQUE : Phishing / Arnaque Avérée';
    summary = `Alerte majeure : cette URL présente de très fortes caractéristiques d’usurpation d’identité numérique${brandMatched ? ` visant la marque ${brandMatched.name}` : ''}. Tout accès comporte un risque critique de vol de données ou d’infection.`;
  } else if (finalScore >= 31) {
    level = 'moderate';
    verdict = 'SUSPICION ÉLEVÉE : Risque Modéré';
    summary = 'Cette adresse comporte des anomalies ou des techniques de masquage (raccourcisseur, TLD inhabituel ou tirets suspects). La prudence absolue est requise.';
  }

  // Recommandations pratiques adaptées
  const recommendations: string[] = [];
  if (level === 'high') {
    recommendations.push('NE CLIQUEZ PAS sur ce lien et ne saisissez aucune information.');
    recommendations.push('Si vous avez reçu cette adresse par e-mail ou SMS, supprimez immédiatement le message.');
    if (brandMatched) {
      recommendations.push(`Rendez-vous directement sur le site officiel de ${brandMatched.name} en tapant vous-même l'adresse officielle (${brandMatched.officialDomains[0]}).`);
    }
    recommendations.push('Si vous avez déjà saisi un mot de passe ou vos coordonnées bancaires sur cette page, changez immédiatement votre mot de passe et contactez votre banque pour faire opposition.');
  } else if (level === 'moderate') {
    recommendations.push('Ne renseignez aucun identifiant personnel ou bancaire sur cette page sans vérification préalable.');
    recommendations.push('Vérifiez l’expéditeur du lien et inspectez attentivement la barre d’adresse de votre navigateur.');
    recommendations.push('Privilégiez l’accès aux services via leur application officielle ou via un moteur de recherche sécurisé.');
  } else {
    recommendations.push('Le domaine semble correspondre aux standards officiels et légitimes.');
    recommendations.push('Restez vigilant : vérifiez toujours le cadenas de sécurité HTTPS et assurez-vous que vous êtes sur le service attendu.');
  }

  return {
    id: `analysis-${Date.now()}`,
    timestamp: Date.now(),
    type: 'url',
    inputSnippet,
    fullInput,
    score: finalScore,
    level,
    verdict,
    summary,
    indicators,
    recommendations,
    domainDetails: decomp,
    urgencyDetected: false,
    brandImpersonationDetected,
    sensitiveDataDetected: false
  };
}

/**
 * Moteur d'analyse complet pour un Message (E-mail ou SMS)
 */
export function analyzeMessageThreat(text: string): AnalysisResult {
  const fullInput = text.trim();
  const inputSnippet = fullInput.length > 80 ? `${fullInput.substring(0, 77)}...` : fullInput;
  const indicators: ThreatIndicator[] = [];
  let score = 0;

  let urgencyDetected = false;
  let sensitiveDataDetected = false;
  let brandImpersonationDetected = false;

  // 1. Analyse de la fausse urgence et manipulation psychologique
  for (const pattern of URGENCY_PATTERNS) {
    const match = fullInput.match(pattern.regex);
    if (match) {
      urgencyDetected = true;
      score += pattern.weight;
      indicators.push({
        id: `urgency-${indicators.length}`,
        category: 'urgency',
        severity: pattern.weight >= 30 ? 'critical' : 'warning',
        title: pattern.label,
        description: `Le message fait appel à la panique ou à l'urgence en mentionnant des expressions sous pression : « ${match[0]} ».`,
        points: pattern.weight,
        evidence: match[0]
      });
    }
  }

  // 2. Analyse des demandes d'identifiants et données sensibles
  for (const pattern of SENSITIVE_DATA_PATTERNS) {
    const match = fullInput.match(pattern.regex);
    if (match) {
      sensitiveDataDetected = true;
      score += pattern.weight;
      indicators.push({
        id: `data-${indicators.length}`,
        category: 'sensitive_data',
        severity: 'critical',
        title: pattern.label,
        description: `Le message vous incite à révéler des éléments ultra-confidentiels : « ${match[0]} ». Les organismes officiels ne demandent JAMAIS ces données par message direct.`,
        points: pattern.weight,
        evidence: match[0]
      });
    }
  }

  // 3. Extraction et inspection des liens/URL présents dans le message
  const urlRegex = /(https?:\/\/[^\s]+|www\.[^\s]+|[a-zA-Z0-9-]+\.(?:xyz|top|tk|com|fr|net|org|info|biz|online|site|app|live|ru)\b[^\s]*)/gi;
  const extractedUrls = fullInput.match(urlRegex) || [];
  let embeddedDomainDetails: DomainDecomposition | undefined;

  if (extractedUrls.length > 0) {
    for (const rawFoundUrl of extractedUrls) {
      const urlAnalysis = analyzeUrlThreat(rawFoundUrl);
      if (urlAnalysis.domainDetails) {
        embeddedDomainDetails = urlAnalysis.domainDetails;
      }
      
      // Injecter les indicateurs pertinents trouvés dans l'URL
      for (const ind of urlAnalysis.indicators) {
        if (ind.points > 0) {
          score += ind.points;
          indicators.push({
            ...ind,
            id: `link-${ind.id}`,
            description: `Lien détecté dans le message (${rawFoundUrl}) : ${ind.description}`
          });
        }
      }
      if (urlAnalysis.brandImpersonationDetected) {
        brandImpersonationDetected = true;
      }
    }
  } else {
    // Si aucun lien direct, vérifier si on mentionne un numéro court de rappel suspect ou WhatsApp
    if (/whatsapp|wa\.me|t\.me|telegram/i.test(fullInput)) {
      score += 20;
      indicators.push({
        id: 'external-messaging',
        category: 'suspicious_domain',
        severity: 'warning',
        title: 'Redirection vers messagerie instantanée tierce (WhatsApp/Telegram)',
        description: 'Les escrocs redirigent fréquemment leurs victimes vers WhatsApp ou Telegram pour échapper aux blocages opérateurs.',
        points: 20
      });
    }
  }

  // 4. Détection de marque mentionnée dans le corps du texte
  for (const brand of KNOWN_BRANDS) {
    const isMentioned = brand.aliases.some(alias => {
      const re = new RegExp(`\\b${alias}\\b`, 'i');
      return re.test(fullInput);
    });

    if (isMentioned) {
      // Si une marque est mentionnée ET qu'une URL est présente sans correspondre à son domaine
      if (extractedUrls.length > 0 && embeddedDomainDetails) {
        const isOfficial = brand.officialDomains.some(off => 
          embeddedDomainDetails?.hostname === off || embeddedDomainDetails?.hostname.endsWith(`.${off}`)
        );

        if (!isOfficial) {
          brandImpersonationDetected = true;
          score += 35;
          indicators.push({
            id: `brand-mismatch-${brand.name}`,
            category: 'typosquatting',
            severity: 'critical',
            title: `Discordance d'identité : Marque « ${brand.name} » usurpée`,
            description: `Le message prétend émaner de ${brand.name}, mais le lien fourni redirige vers « ${embeddedDomainDetails.hostname} », qui n'a aucun lien avec les serveurs officiels (${brand.officialDomains.join(', ')}).`,
            points: 35,
            evidence: `Marque prétendue : ${brand.name} → Lien réel : ${embeddedDomainDetails.hostname}`
          });
        }
      }
    }
  }

  // 5. Salutation impersonnelle ou générique
  if (/^(cher\s+client|cher\s+adhérent|cher\s+utilisateur|bonjour\s+monsieur\/madame|dear\s+customer)/i.test(fullInput.trim())) {
    score += 10;
    indicators.push({
      id: 'generic-greeting',
      category: 'grammar_style',
      severity: 'info',
      title: 'Salutation générique non personnalisée',
      description: 'Les messages de masse de phishing utilisent souvent une formule vague (« Cher client ») car ils ne connaissent pas votre véritable nom et prénom.',
      points: 10,
      evidence: 'Cher client / utilisateur'
    });
  }

  // 6. Fautes d'orthographe ou formulation artificielle
  const syntaxErrors = [
    { regex: /veuillez\s+de\s+vous\s+connecter/i, label: 'Formulation bancale de traduction automatique' },
    { regex: /mettre\s+a\s+jour\s+votre\s+carte\s+vitale/i, label: 'Absence d\'accentuation et syntaxe SMS frauduleux' },
    { regex: /vos\s+service\s+sera/i, label: 'Désaccord grammatical grossier' },
    { regex: /clique\s+sur\s+ce\s+lien/i, label: 'Tutoiement inhabituel dans un message formel' },
  ];
  for (const syn of syntaxErrors) {
    if (syn.regex.test(fullInput)) {
      score += 15;
      indicators.push({
        id: `syntax-${indicators.length}`,
        category: 'grammar_style',
        severity: 'warning',
        title: 'Anomalie linguistique / Syntaxe suspecte',
        description: `Présence d'anomalies de rédaction : ${syn.label}.`,
        points: 15
      });
    }
  }

  // Normalisation du score
  const finalScore = Math.max(0, Math.min(100, score));

  // Attribution du niveau de risque
  let level: RiskLevel = 'low';
  let verdict = 'Message Vraisemblablement Légitime';
  let summary = 'Ce message ne contient aucun des leviers psychologiques classiques d’intimidation, ni de lien manifestement malveillant.';

  if (finalScore >= 70) {
    level = 'high';
    verdict = 'DANGER CRITIQUE : Phishing / Hameçonnage Confirmé';
    summary = 'Ce message réunit tous les critères d’une arnaque cybercriminelle : manipulation psychologique, sentiment d’urgence artificielle et/ou détournement de marque. Le but est de voler vos données personnelles ou bancaires.';
  } else if (finalScore >= 31) {
    level = 'moderate';
    verdict = 'ATTENTION : Suspicion Modérée';
    summary = 'Ce message présente plusieurs indices suspects (ton pressant, lien externe ou demande d\'action inhabituelle). Ne cliquez sur rien sans vérification préalable.';
  }

  // Recommandations pratiques
  const recommendations: string[] = [];
  if (level === 'high') {
    recommendations.push('Ne cliquez sur AUCUN lien et ne répondez sous aucun prétexte à ce message.');
    recommendations.push('Supprimez immédiatement ce message (ou signalez-le au 33700 pour un SMS en France, ou à Signal-Spam).');
    recommendations.push('Votre banque ou l\'Assurance Maladie ne vous demandera JAMAIS de mot de passe ou code confidentiel par message.');
    recommendations.push('Si vous avez un doute, connectez-vous séparément depuis votre navigateur ou votre application officielle habituelle.');
  } else if (level === 'moderate') {
    recommendations.push('Examinez attentivement l\'adresse de l\'expéditeur réel (pas seulement le nom affiché).');
    recommendations.push('Ne téléchargez aucune pièce jointe provenant de ce message.');
    recommendations.push('Contactez l\'organisme par votre moyen de contact habituel (téléphone officiel, application dédiée) pour vérifier la demande.');
  } else {
    recommendations.push('Le message semble légitime, mais continuez d\'appliquer les règles élémentaires d\'hygiène numérique.');
    recommendations.push('Ne communiquez jamais vos codes bancaires ou mots de passe, même en cas de demande bien formulée.');
  }

  return {
    id: `analysis-${Date.now()}`,
    timestamp: Date.now(),
    type: 'message',
    inputSnippet,
    fullInput,
    score: finalScore,
    level,
    verdict,
    summary,
    indicators,
    recommendations,
    domainDetails: embeddedDomainDetails,
    urgencyDetected,
    brandImpersonationDetected,
    sensitiveDataDetected
  };
}
