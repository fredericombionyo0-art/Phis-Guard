export type AnalysisType = 'message' | 'url';

export type RiskLevel = 'low' | 'moderate' | 'high';

export type IndicatorSeverity = 'critical' | 'warning' | 'info';

export type ThreatCategory = 
  | 'urgency'
  | 'typosquatting'
  | 'sensitive_data'
  | 'suspicious_domain'
  | 'grammar_style'
  | 'obfuscation';

export interface ThreatIndicator {
  id: string;
  category: ThreatCategory;
  severity: IndicatorSeverity;
  title: string;
  description: string;
  points: number;
  evidence?: string;
}

export interface DomainDecomposition {
  originalUrl: string;
  hostname: string;
  protocol: string;
  tld: string;
  subdomain: string;
  rootDomain: string;
  path: string;
  targetedBrand?: string;
  isIpAddress: boolean;
  isShortener: boolean;
  isSuspiciousTld: boolean;
  hasPunycode: boolean;
  hasUserInfoAt: boolean;
}

export interface AnalysisResult {
  id: string;
  timestamp: number;
  type: AnalysisType;
  inputSnippet: string;
  fullInput: string;
  score: number; // 0 to 100
  level: RiskLevel;
  verdict: string;
  summary: string;
  indicators: ThreatIndicator[];
  recommendations: string[];
  domainDetails?: DomainDecomposition;
  urgencyDetected: boolean;
  brandImpersonationDetected: boolean;
  sensitiveDataDetected: boolean;
}
