/**
 * System Prompt & Pydantic Schema Specification for Gemini EML Threat Forensic Investigation
 */

export const GEMINI_SYSTEM_PROMPT = `You are T.R.A.C.E (Threat Reconnaissance, Analysis & Cyber Forensics Engine), an elite Senior Digital Forensics and Incident Response (DFIR) specialist and Cyber Threat Intelligence Analyst.

Your objective is to conduct a rigorous, deterministic, logical forensic investigation on raw RFC 5322/822 .EML email data. You must identify what the email is, dissect its authenticity, evaluate its trust score, calculate its threat score (0-100), trace its transmission chain, and generate an exhaustive technical forensic report in both structured JSON format and a polished, standalone HTML forensic report.

### Forensic Investigation Methodology:

1. IDENTIFICATION & CLASSIFICATION:
   - Identify the exact email category: phishing, bec_scam (Business Email Compromise), malware_delivery, credential_harvesting, spoofing, spam_marketing, or legitimate.
   - Extract primary metadata: Message-ID, Subject, Date, Claimed Sender, Envelope-From, Recipient, Reply-To.

2. DOMAIN & IDENTITY INTEGRITY:
   - Perform strict domain cross-checks between Header-From, Return-Path, Reply-To, Envelope-From, and DKIM signing domain (d=).
   - Detect domain lookalikes (typosquatting, combopreservation, punycode, cousin domains such as brand-alert.test vs brand.com).
   - Flag reply-to diverters (e.g. email claims to be an executive at company.com but replies redirect to a free webmail service).

3. HOP-TO-HOP IP ROUTE ANALYSIS:
   - Reconstruct the transmission route chronologically from the bottom-most 'Received:' header (True Originating MTA) up to the topmost Inbound Gateway MX.
   - For each hop, extract: Hop Number, Source Host (from), Receiving Host (by), Transport Protocol (ESMTPS, SMTP, TLS cipher), Client IP, and Timestamp.
   - Detect routing anomalies: Dynamic/residential ISP pools, offshore bulletproof relays, proxy hops, timestamp skews, geolocation contradictions (e.g. US bank routed via Eastern Europe or unfamiliar VPS).

4. PROTOCOL AUTHENTICATION AUDIT:
   - SPF (Sender Policy Framework): Audit 'Received-SPF' and 'Authentication-Results' (pass, fail, softfail, neutral). Verify if originating client IP is authorized.
   - DKIM (DomainKeys Identified Mail): Inspect signature presence, cryptographic algorithm (rsa-sha256), signing domain (d=), header alignment with Header-From.
   - DMARC: Evaluate policy compliance (p=none, p=quarantine, p=reject). Check SPF alignment and DKIM alignment.
   - ARC (Authenticated Received Chain): Inspect ARC-Seal, ARC-Message-Signature, and ARC-Authentication-Results for enterprise relay integrity.

5. PSYCHOLOGICAL & SOCIAL ENGINEERING HEURISTICS:
   - Evaluate artificial urgency (e.g. 'Within 24 hours', 'immediate action required').
   - Evaluate fear, loss-of-service, or account limitation threats.
   - Evaluate authority impersonation (Bank Fraud Team, CEO, HR, IT Support).
   - Evaluate deceptive calls-to-action (gift card purchases, credential logins, wire transfers, urgent invoice reconciliations).

6. PAYLOAD & ASSET INSPECTION (URLs & ATTACHMENTS):
   - Extract all embedded hyperlinks and compare anchor text vs actual destination href.
   - Inspect tracking redirects, open redirects, shortened URLs, or suspicious TLDs.
   - Inspect MIME multipart boundaries, embedded images, base64 payload signatures, macro-enabled docs, executable disguised filenames, and QR codes / screenshot lures.

7. MINUTE FORENSIC ARTIFACTS:
   - Analyze Message-ID syntax and entropy (valid FQDN vs forged generator syntax).
   - Inspect X-Originating-IP, X-Mailer / User-Agent, X-Priority / Importance flags, Content-Transfer-Encoding.
   - Calculate final Threat Score (0 to 100, where 100 is severe malicious threat) and Trust Score (0 to 100, where 100 is pristine authenticated corporate mail).

8. OUTPUT FORMAT:
   Return valid JSON containing two top-level keys:
   - "score": Contains threat_score, trust_score, threat_level, category, confidence.
   - "report": Contains executive_summary, point_wise_findings, verdict_reasoning, domain_analysis, hop_to_hop_trace, authentication_results, social_engineering, urls_analyzed, attachments_analyzed, minute_technical_details, soc_remediation_steps, and forensic_html.

The 'forensic_html' field must be a complete, elegant, self-contained HTML forensic document designed for a SOC incident response dossier, with styled tables, visual alert boxes, hop trace route, indicator badges, and remediation plan.`;

export const PYDANTIC_CLASS_DEFINITION = `"""
Pydantic Models for T.R.A.C.E EML Forensic Investigation Engine
Compatible with Pydantic v2 and Gemini API response_schema
"""

from typing import List, Optional, Literal
from pydantic import BaseModel, Field


class HopTraceNode(BaseModel):
    hop_number: int = Field(..., description="Chronological hop index (1 = originating client/MTA)")
    from_host: str = Field(..., description="Claimed or resolved source hostname")
    by_host: str = Field(..., description="Receiving mail transfer agent hostname")
    ip: str = Field(..., description="Extracted IP address for this hop")
    protocol: Optional[str] = Field("ESMTPS", description="Transfer protocol and cipher if available")
    timestamp: Optional[str] = Field(None, description="RFC 2822 or ISO timestamp of the relay")
    delay_seconds: Optional[int] = Field(0, description="Transit delay from previous hop in seconds")
    is_origin: bool = Field(False, description="True if this is the initial originating sender MTA")
    is_suspicious: bool = Field(False, description="True if IP/host shows suspicious traits (e.g. dynamic dialup, spam relay)")
    notes: Optional[str] = Field(None, description="Forensic notes regarding this relay hop")


class DomainAnalysis(BaseModel):
    header_from: str = Field(..., description="Address displayed in the 'From:' header")
    return_path: str = Field(..., description="Envelope bounce address in 'Return-Path:'")
    reply_to: Optional[str] = Field(None, description="Configured 'Reply-To:' address")
    dkim_domain: Optional[str] = Field(None, description="Domain found in DKIM d= parameter")
    envelope_from: Optional[str] = Field(None, description="smtp.mailfrom envelope address")
    is_mismatch: bool = Field(..., description="True if display domain differs from envelope or signing domain")
    lookalike_risk: Literal["none", "low", "moderate", "high"] = Field(..., description="Risk of typosquatting or cousin domain")
    notes: str = Field(..., description="Detailed domain alignment evaluation")


class AuthCheck(BaseModel):
    protocol: Literal["SPF", "DKIM", "DMARC", "ARC"] = Field(..., description="Authentication standard")
    status: Literal["pass", "fail", "softfail", "neutral", "none"] = Field(..., description="Validation outcome")
    aligned: bool = Field(..., description="Whether identifier alignment passed for DMARC")
    details: str = Field(..., description="Diagnostic details from Authentication-Results")


class SocialEngineeringIndicator(BaseModel):
    tactic: str = Field(..., description="Name of deception tactic (e.g., Artificial Urgency, Authority Impersonation)")
    detected: bool = Field(..., description="Whether this indicator was present in the content")
    severity: Literal["low", "medium", "high"] = Field(..., description="Impact level of this indicator")
    evidence: str = Field(..., description="Exact quotes or signals extracted from the email")


class ExtractedUrl(BaseModel):
    url: str = Field(..., description="Full URL extracted from HTML or plain text body")
    display_domain: str = Field(..., description="Domain seen or implied by link text")
    actual_destination: str = Field(..., description="Real host domain the URL leads to")
    is_lookalike: bool = Field(..., description="True if URL mimics an authentic brand or service")
    is_redirect_tracker: bool = Field(..., description="True if URL uses click-tracking redirect parameters")
    risk_rating: Literal["safe", "suspicious", "malicious"] = Field(..., description="Assessed threat level of this link")
    notes: str = Field(..., description="Forensic context on URL payload")


class AttachmentDetail(BaseModel):
    filename: str = Field(..., description="Attachment filename")
    content_type: str = Field(..., description="MIME content-type (e.g. image/png, application/pdf)")
    size_bytes: Optional[int] = Field(None, description="Estimated or parsed byte size")
    is_executable_or_suspicious: bool = Field(..., description="True if file type poses code execution risk")
    notes: str = Field(..., description="Forensic inspection notes")


class MinuteTechnicalDetails(BaseModel):
    message_id_validity: str = Field(..., description="Evaluation of Message-ID header syntax and legitimacy")
    mailer_software: Optional[str] = Field(None, description="X-Mailer or User-Agent header value if present")
    character_encoding: Optional[str] = Field(None, description="MIME charset and transfer encoding")
    anomalous_headers: List[str] = Field(default_factory=list, description="Headers that deviate from RFC compliance or flag high spam scores")
    priority_flag: str = Field("Normal", description="X-Priority, Importance, or Urgent markers")


# Top-Level Output Components as requested: "score" and "report"

class Score(BaseModel):
    threat_score: int = Field(..., ge=0, le=100, description="Overall threat score (0 = completely safe, 100 = critical threat)")
    trust_score: int = Field(..., ge=0, le=100, description="Overall trust score (0 = zero trust, 100 = verified safe)")
    threat_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"] = Field(..., description="Threat severity tier")
    category: Literal[
        "phishing", 
        "bec_scam", 
        "malware_delivery", 
        "credential_harvesting", 
        "spoofing", 
        "spam_marketing", 
        "legitimate"
    ] = Field(..., description="Classified email typology")
    confidence: int = Field(..., ge=0, le=100, description="Forensic confidence index (0 to 100)")


class Report(BaseModel):
    executive_summary: str = Field(..., description="High-level paragraph for CISO and SOC managers")
    point_wise_findings: List[str] = Field(..., description="Granular bullet points of all forensic discoveries")
    verdict_reasoning: str = Field(..., description="Logical justification linking evidence to threat score")
    domain_analysis: DomainAnalysis = Field(..., description="Domain alignment and spoofing breakdown")
    hop_to_hop_trace: List[HopTraceNode] = Field(..., description="Chronological MTA hop reconstruction")
    authentication_results: List[AuthCheck] = Field(..., description="SPF, DKIM, DMARC, ARC audit results")
    social_engineering: List[SocialEngineeringIndicator] = Field(..., description="Deception and manipulation indicators")
    urls_analyzed: List[ExtractedUrl] = Field(default_factory=list, description="All body links inspected")
    attachments_analyzed: List[AttachmentDetail] = Field(default_factory=list, description="All attachments inspected")
    minute_technical_details: MinuteTechnicalDetails = Field(..., description="RFC header artifacts and technical anomalies")
    soc_remediation_steps: List[str] = Field(..., description="Prescriptive action items for incident responders")
    forensic_html: str = Field(..., description="Fully styled standalone HTML forensic report for dossier export and PDF conversion")


class EmailForensicInvestigation(BaseModel):
    """
    Root output container returned by Gemini API containing 'score' and 'report'
    """
    score: Score = Field(..., description="Numerical scoring and categorical verdict")
    report: Report = Field(..., description="Comprehensive forensic dossier, hop trace, tables, and HTML report")
`;

export const PYTHON_GEMINI_CALL_EXAMPLE = `import os
from google import genai
from google.genai import types
from pydantic_models import EmailForensicInvestigation

# Initialize Gemini Client
client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

# Read .eml file content
with open("suspicious_email.eml", "r", encoding="utf-8") as f:
    eml_content = f.read()

# Execute Investigation with Gemini 3.8 Flash & Structured Pydantic Output
response = client.models.generate_content(
    model="gemini-3.8-flash",
    contents=f"Perform deep logical forensic investigation on this raw .eml message:\\n\\n{eml_content}",
    config=types.GenerateContentConfig(
        system_instruction=GEMINI_SYSTEM_PROMPT,
        response_mime_type="application/json",
        response_schema=EmailForensicInvestigation,
        temperature=0.1,  # Low temperature for strict deterministic forensics
    ),
)

# Parse response into Pydantic model
investigation = EmailForensicInvestigation.model_validate_json(response.text)

print(f"Threat Score: {investigation.score.threat_score}/100 ({investigation.score.threat_level})")
print(f"Trust Score: {investigation.score.trust_score}/100")
print(f"Summary: {investigation.report.executive_summary}")
`;
