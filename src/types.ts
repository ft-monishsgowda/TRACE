export type ThreatLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE';

export type ThreatCategory = 
  | 'phishing' 
  | 'bec_scam' 
  | 'malware_delivery' 
  | 'credential_harvesting' 
  | 'spoofing' 
  | 'spam_marketing' 
  | 'legitimate';

export interface HopTraceNode {
  hopNumber: number;
  fromHost: string;
  byHost: string;
  ip: string;
  protocol?: string;
  timestamp?: string;
  delaySeconds?: number;
  isOrigin: boolean;
  isSuspicious: boolean;
  notes?: string;
  geoOrAsn?: string;
}

export interface DomainCheck {
  headerFrom: string;
  returnPath: string;
  replyTo?: string;
  dkimDomain?: string;
  envelopeFrom?: string;
  isMismatch: boolean;
  lookalikeRisk: 'none' | 'low' | 'moderate' | 'high';
  notes: string;
}

export interface AuthCheck {
  protocol: 'SPF' | 'DKIM' | 'DMARC' | 'ARC';
  status: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none';
  aligned: boolean;
  details: string;
}

export interface SocialEngineeringIndicator {
  tactic: string; // e.g. "Artificial Urgency", "Authority Impersonation", "Fear of Loss", "Call-to-Action Pressure"
  detected: boolean;
  severity: 'low' | 'medium' | 'high';
  evidence: string;
}

export interface ExtractedUrl {
  url: string;
  displayDomain: string;
  actualDestination: string;
  isLookalike: boolean;
  isRedirectTracker: boolean;
  riskRating: 'safe' | 'suspicious' | 'malicious';
  notes: string;
}

export interface AttachmentDetail {
  filename: string;
  contentType: string;
  sizeBytes?: number;
  isExecutableOrSuspicious: boolean;
  notes: string;
  isImage?: boolean;
  imageDataUrl?: string;
  imageDescription?: string; // 2-line forensic description
  sha256?: string;
}

export interface InvestigationScore {
  threat_score: number; // 0 - 100 (100 = critical threat)
  trust_score: number;  // 0 - 100 (100 = completely trustworthy)
  threat_level: ThreatLevel;
  category: ThreatCategory;
  confidence: number;   // 0 - 100
}

export interface InvestigationReport {
  executive_summary: string;
  point_wise_findings: string[];
  verdict_reasoning: string;
  domain_analysis: DomainCheck;
  hop_to_hop_trace: HopTraceNode[];
  authentication_results: AuthCheck[];
  social_engineering: SocialEngineeringIndicator[];
  urls_analyzed: ExtractedUrl[];
  attachments_analyzed: AttachmentDetail[];
  minute_technical_details?: {
    messageIdValidity?: string;
    mailerSoftware?: string;
    characterEncoding?: string;
    anomalousHeaders?: string[];
    priorityFlag?: string;
    detectedLanguage?: string;
  };
  soc_remediation_steps: string[];
  forensic_html: string; // The complete standalone HTML forensic report
}

export interface EmailForensicResult {
  id: string;
  timestamp: string;
  subject: string;
  sender: string;
  recipient: string;
  detectedLanguage?: {
    code: string;
    name: string;
    nativeName?: string;
    confidence: number;
  };
  score: InvestigationScore;
  report: InvestigationReport;
  rawEmlSampleName?: string;
  syncedToSupabase?: boolean;
  source?: string;
  engineNotice?: string;
}

export interface SupabaseThreatRecord {
  id?: string;
  created_at?: string;
  subject: string;
  sender: string;
  recipient: string;
  threat_score: number;
  trust_score: number;
  threat_level: string;
  category: string;
  indicators_count: number;
  origin_ip?: string;
  forensic_html?: string;
  raw_eml_snippet?: string;
  soc_verdict?: string;
}
