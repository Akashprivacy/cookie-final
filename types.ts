

export enum CookieCategory {
  NECESSARY = 'Necessary',
  ANALYTICS = 'Analytics',
  MARKETING = 'Marketing',
  FUNCTIONAL = 'Functional',
  UNKNOWN = 'Unknown',
}

export enum FilterCategory {
    ALL = 'All Technologies',
    TRACKERS = 'Trackers',
    VIOLATIONS = 'Violations',
    NECESSARY = 'Necessary',
    ANALYTICS = 'Analytics',
    MARKETING = 'Marketing',
    FUNCTIONAL = 'Functional',
    UNKNOWN = 'Unknown',
}

export type ComplianceStatus = 'Compliant' | 'Pre-Consent Violation' | 'Post-Rejection Violation' | 'Unknown';
export type CookieParty = 'First' | 'Third';
export type RiskLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational' | 'Unknown';


export interface CookieInfo {
  key: string;
  name: string;
  provider: string;
  category: CookieCategory | string;
  expiry: string;
  purpose: string;
  party: CookieParty;
  isHttpOnly: boolean;
  isSecure: boolean;
  complianceStatus: ComplianceStatus;
}

export interface TrackerInfo {
    key: string;
    url: string;
    provider: string;
    category: CookieCategory | string;
    complianceStatus: ComplianceStatus;
}

export interface ComplianceInfo {
    riskLevel: RiskLevel;
    assessment: string;
}

export interface ScanResultData {
  cookies: CookieInfo[];
  trackers: TrackerInfo[];
  screenshotBase64: string;
  compliance: {
    gdpr: ComplianceInfo;
    ccpa: ComplianceInfo;
  };
  consentBannerDetected: boolean;
  pagesScannedCount: number;
}

// --- Legal Review Types ---
export type LegalPerspective = 'controller' | 'processor' | 'neutral';

export interface ClauseAnalysis {
  clause: string;
  summary: string;
  risk: string;
  riskLevel: RiskLevel;
  recommendation: string;
}

export interface LegalAnalysisResult {
  overallRisk: {
    level: RiskLevel;
    summary: string;
  };
  analysis: ClauseAnalysis[];
}

export interface GeneratedContract {
    title: string;
    content: string;
}

export interface ChatMessage {
    sender: 'user' | 'ai';
    text: string;
}

export interface ContractTemplate {
    id: string;
    name: string;
    content: string;
}


// --- Vulnerability Scanner Types ---
export type VulnerabilityCategory = 'Security Headers' | 'Cookie Configuration' | 'Information Exposure' | 'Insecure Transport' | 'Software Fingerprinting' | 'Frontend Security' | 'Third-Party Risk' | 'Best Practices' | 'Unknown';

export interface VulnerabilityFinding {
    name: string;
    riskLevel: RiskLevel;
    category: VulnerabilityCategory | string;
    description: string;
    impact: string;
    evidence: string;
    remediation: string;
    references: {
        title: string;
        url: string;
    }[];
}

export interface VulnerabilityScanResult {
    overallRisk: {
        level: RiskLevel;
        score: number; // 0.0 - 10.0
        summary: string;
    };
    findings: VulnerabilityFinding[];
}