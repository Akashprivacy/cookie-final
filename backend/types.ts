// This file defines types shared within the backend service.

export enum CookieCategory {
  NECESSARY = 'Necessary',
  ANALYTICS = 'Analytics',
  MARKETING = 'Marketing',
  FUNCTIONAL = 'Functional',
  UNKNOWN = 'Unknown',
}

export enum ComplianceStatus {
  COMPLIANT = 'Compliant',
  PRE_CONSENT_VIOLATION = 'Pre-Consent Violation',
  POST_REJECTION_VIOLATION = 'Post-Rejection Violation',
  UNKNOWN = 'Unknown',
}

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
  complianceStatus: ComplianceStatus | string;
}

export interface TrackerInfo {
    key: string;
    url: string;
    provider: string;
    category: CookieCategory | string;
    complianceStatus: ComplianceStatus | string;
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


// --- Legal Reviewer Types ---
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

export enum VulnerabilityCategory {
  SECURITY_HEADERS = 'Security Headers',
  COOKIE_CONFIG = 'Cookie Configuration',
  INFO_EXPOSURE = 'Information Exposure',
  INSECURE_TRANSPORT = 'Insecure Transport',
  SOFTWARE_FINGERPRINTING = 'Software Fingerprinting',
  FRONTEND_SECURITY = 'Frontend Security',
  THIRD_PARTY_RISK = 'Third-Party Risk',
  BEST_PRACTICES = 'Best Practices',
  UNKNOWN = 'Unknown',
}

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