import React, { useEffect, useRef } from 'react';
import {
  EmailForensicResult,
  HopTraceNode,
  AuthCheck,
  SocialEngineeringIndicator,
  ExtractedUrl,
  AttachmentDetail,
  DomainCheck,
} from '../types';
import {
  ShieldAlert,
  Shield,
  Layers,
  Globe,
  Lock,
  Download,
  FileCode,
  Database,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  HelpCircle,
  ExternalLink,
  Paperclip,
} from 'lucide-react';
import { animateNumber, animateGaugeCircle, animateStaggerItems, animateViewTransition, initScrollReveal } from '../utils/animations';
import { ThreatTrendHeatmap } from './ThreatTrendHeatmap';

interface GraphicalDashboardProps {
  result: EmailForensicResult;
  onViewReport: () => void;
  onDownloadPdf: () => void;
  onSyncToSupabase: () => void;
  isSyncing: boolean;
  syncSuccess: boolean;
}

export const GraphicalDashboard: React.FC<GraphicalDashboardProps> = ({
  result,
  onViewReport,
  onDownloadPdf,
  onSyncToSupabase,
  isSyncing,
  syncSuccess,
}) => {
  const score = result.score || { threat_score: 0, trust_score: 100, threat_level: 'SAFE', category: 'legitimate', confidence: 90 };
  const report = result.report || ({} as any);
  const subject = result.subject || '(No Subject)';
  const sender = result.sender || 'Unknown';
  const recipient = result.recipient || 'Unknown';
  const timestamp = result.timestamp || new Date().toISOString();

  // Normalized safe accessors
  const minuteDetails = report.minute_technical_details || {};
  const hopTrace: HopTraceNode[] = report.hop_to_hop_trace || [];
  const pointFindings: string[] = report.point_wise_findings || [];
  const authResults: AuthCheck[] = report.authentication_results || [];
  const socialEng: SocialEngineeringIndicator[] = report.social_engineering || [];
  const urlsAnalyzed: ExtractedUrl[] = report.urls_analyzed || [];
  const attachmentsAnalyzed: AttachmentDetail[] = report.attachments_analyzed || [];
  const domainAnalysis: DomainCheck = report.domain_analysis || {
    headerFrom: sender,
    returnPath: sender,
    isMismatch: false,
    lookalikeRisk: 'Low',
    notes: 'Header verification baseline',
  };
  const remediationSteps: string[] = report.soc_remediation_steps || [];

  const dashboardContainerRef = useRef<HTMLDivElement>(null);
  const threatNumberRef = useRef<HTMLSpanElement>(null);
  const trustNumberRef = useRef<HTMLSpanElement>(null);
  const threatCircleRef = useRef<SVGCircleElement>(null);
  const trustCircleRef = useRef<SVGCircleElement>(null);

  useEffect(() => {
    // Smooth view entrance
    if (dashboardContainerRef.current) {
      animateViewTransition(dashboardContainerRef.current);
    }

    // Number counters
    const threatVal = score.threat_score || 0;
    const trustVal = score.trust_score || 0;
    animateNumber(threatNumberRef.current, 0, threatVal, 850);
    animateNumber(trustNumberRef.current, 0, trustVal, 850);

    // SVG radial gauge fill
    const circumference = 289;
    const threatTargetOffset = circumference - (circumference * threatVal) / 100;
    const trustTargetOffset = circumference - (circumference * trustVal) / 100;

    animateGaugeCircle(threatCircleRef.current, threatTargetOffset, circumference, 1000);
    animateGaugeCircle(trustCircleRef.current, trustTargetOffset, circumference, 1000);

    // Stagger hop cards and findings
    setTimeout(() => {
      animateStaggerItems('.hop-card-item', 50);
    }, 100);

    // Tiny minimal scroll reveal observer for lower dashboard cards
    const cleanupScroll = initScrollReveal('.scroll-reveal-item');
    return () => cleanupScroll();
  }, [result]);

  const getLevelBadgeClass = (level: string) => {
    switch (level) {
      case 'CRITICAL':
      case 'HIGH':
        return 'bg-[#181818] text-[#fafafa] border-[#fafafa] font-bold';
      case 'MEDIUM':
        return 'bg-[#181818] text-[#ebeced] border-[#5c5c61] font-medium';
      default:
        return 'bg-[#181818] text-[#a1a1aa] border-[#5c5c61] font-normal';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status.toLowerCase()) {
      case 'pass':
        return <CheckCircle2 className="w-4 h-4 text-[#fafafa]" />;
      case 'fail':
        return <XCircle className="w-4 h-4 text-[#a1a1aa]" />;
      case 'softfail':
      case 'neutral':
        return <AlertTriangle className="w-4 h-4 text-[#a1a1aa]" />;
      default:
        return <HelpCircle className="w-4 h-4 text-[#5c5c61]" />;
    }
  };

  return (
    <div ref={dashboardContainerRef} className="w-full max-w-[1200px] mx-auto px-3.5 sm:px-6 pt-18 sm:pt-20 pb-28 md:pb-24 flex flex-col gap-4 sm:gap-6">
      {/* Top Banner with Subject & Quick Actions */}
      <div className="card-console flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 sm:p-6">
        <div className="flex flex-col gap-1.5 w-full">
          <div className="flex flex-wrap items-center gap-1.5 sm:gap-2">
            <span className={`text-[11px] font-mono px-2.5 py-0.5 rounded border ${getLevelBadgeClass(score.threat_level)}`}>
              {score.threat_level} THREAT
            </span>
            <span className="text-[11px] font-mono text-[#a1a1aa] bg-[#181818] px-2 py-0.5 rounded border border-[#5c5c61]">
              {score.category.toUpperCase().replace('_', ' ')}
            </span>
            <span className="text-[11px] font-mono text-[#a1a1aa]">
              Confidence: {score.confidence}%
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#181818] border border-[#5c5c61] text-[#fafafa]">
              {result.source ? (result.source.includes('gemini') ? `AI: ${result.source}` : 'Engine: Deterministic DFIR') : 'Engine: DFIR Core'}
            </span>
          </div>
          {result.engineNotice && (
            <div className="mt-1 px-3 py-1 rounded bg-[#181818] border border-[#5c5c61] text-[11px] text-[#ebeced] font-sans flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[#fafafa] shrink-0 animate-pulse" />
              <span>{result.engineNotice}</span>
            </div>
          )}
          <h2 className="text-base sm:text-xl font-mono font-medium text-[#fafafa] mt-1 break-words leading-snug">
            {subject}
          </h2>
          <div className="flex flex-col sm:flex-row sm:flex-wrap items-start sm:items-center gap-x-4 gap-y-1 text-xs text-[#a1a1aa] font-sans">
            <span className="break-all"><strong>From:</strong> {sender}</span>
            <span className="break-all"><strong>To:</strong> {recipient}</span>
            <span><strong>Time:</strong> {new Date(timestamp).toLocaleString()}</span>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="grid grid-cols-1 sm:grid-cols-3 md:flex md:items-center gap-2 sm:gap-2.5 w-full md:w-auto shrink-0 pt-2 md:pt-0 border-t md:border-t-0 border-[#5c5c61]/40">
          <button
            onClick={onDownloadPdf}
            className="btn-pill-primary text-xs py-2.5 px-4 cursor-pointer w-full md:w-auto justify-center min-h-[42px]"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download PDF</span>
          </button>

          <button
            onClick={onViewReport}
            className="btn-pill-ghost text-xs py-2.5 px-4 cursor-pointer w-full md:w-auto justify-center min-h-[42px]"
          >
            <FileCode className="w-3.5 h-3.5 text-[#a1a1aa]" />
            <span>View HTML Dossier</span>
          </button>

          <button
            onClick={onSyncToSupabase}
            disabled={isSyncing}
            className="btn-pill-ghost text-xs py-2.5 px-4 cursor-pointer w-full md:w-auto justify-center min-h-[42px]"
          >
            <Database className={`w-3.5 h-3.5 text-[#a1a1aa] ${isSyncing ? 'animate-spin' : ''}`} />
            <span>{isSyncing ? 'Syncing...' : syncSuccess ? 'Saved to DB' : 'Save to Supabase'}</span>
          </button>
        </div>
      </div>

      {/* SECTION 1: Pictorial Threat Gauges & Executive Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 sm:gap-6">
        {/* Threat & Trust Scores Radial Cards */}
        <div className="lg:col-span-4 grid grid-cols-2 sm:grid-cols-2 lg:grid-cols-1 gap-3 sm:gap-4">
          {/* Threat Gauge */}
          <div className="card-console card-hover-highlight flex flex-col items-center justify-center text-center relative overflow-hidden p-3.5 sm:p-6">
            <div className="flex items-center justify-between w-full mb-1 sm:mb-2">
              <span className="text-[10px] sm:text-[11px] font-mono tracking-wider text-[#a1a1aa] uppercase">
                Threat Score
              </span>
              <span className="text-[9px] sm:text-[10px] font-mono text-[#a1a1aa] bg-[#181818] px-1.5 py-0.5 rounded border border-[#5c5c61]">
                RFC 5322
              </span>
            </div>
            <div className="relative flex items-center justify-center my-2 sm:my-3">
              <svg className="w-22 h-22 sm:w-28 sm:h-28 transform -rotate-90">
                <circle
                  cx="44"
                  cy="44"
                  r="36"
                  className="sm:hidden"
                  stroke="#181818"
                  strokeWidth="7"
                  fill="transparent"
                />
                <circle
                  cx="56"
                  cy="56"
                  r="46"
                  className="hidden sm:block"
                  stroke="#181818"
                  strokeWidth="8"
                  fill="transparent"
                />
                <circle
                  ref={threatCircleRef}
                  cx="56"
                  cy="56"
                  r="46"
                  stroke="#fafafa"
                  strokeWidth="8"
                  strokeDasharray={289}
                  strokeDashoffset={289}
                  strokeLinecap="round"
                  fill="transparent"
                />
              </svg>
              <div className="absolute flex flex-col items-center">
                <span ref={threatNumberRef} className="font-mono text-2xl sm:text-3xl font-semibold text-[#fafafa]">
                  {score.threat_score}
                </span>
                <span className="text-[9px] sm:text-[10px] font-mono text-[#a1a1aa]">/ 100</span>
              </div>
            </div>
            <span className="text-[11px] sm:text-xs font-sans text-[#ebeced] leading-tight">
              {score.threat_score > 70 ? 'High Risk Profile' : score.threat_score > 30 ? 'Suspicious Indicators' : 'Verified Baseline'}
            </span>
          </div>

          {/* Trust Gauge */}
          <div className="card-console card-hover-highlight flex flex-col items-center justify-center text-center relative overflow-hidden p-3.5 sm:p-6">
            <div className="flex items-center justify-between w-full mb-1 sm:mb-2">
              <span className="text-[10px] sm:text-[11px] font-mono tracking-wider text-[#a1a1aa] uppercase">
                Trust Score
              </span>
              <span className="text-[9px] sm:text-[10px] font-mono text-[#a1a1aa] bg-[#181818] px-1.5 py-0.5 rounded border border-[#5c5c61]">
                DKIM / SPF
              </span>
            </div>
            <div className="relative flex items-center justify-center my-2 sm:my-3">
              <svg className="w-22 h-22 sm:w-28 sm:h-28 transform -rotate-90">
                <circle
                  cx="44"
                  cy="44"
                  r="36"
                  className="sm:hidden"
                  stroke="#181818"
                  strokeWidth="7"
                  fill="transparent"
                />
                <circle
                  cx="56"
                  cy="56"
                  r="46"
                  className="hidden sm:block"
                  stroke="#181818"
                  strokeWidth="8"
                  fill="transparent"
                />
                <circle
                  ref={trustCircleRef}
                  cx="56"
                  cy="56"
                  r="46"
                  stroke="#a1a1aa"
                  strokeWidth="8"
                  strokeDasharray={289}
                  strokeDashoffset={289}
                  strokeLinecap="round"
                  fill="transparent"
                />
              </svg>
              <div className="absolute flex flex-col items-center">
                <span ref={trustNumberRef} className="font-mono text-2xl sm:text-3xl font-semibold text-[#fafafa]">
                  {score.trust_score}
                </span>
                <span className="text-[9px] sm:text-[10px] font-mono text-[#a1a1aa]">/ 100</span>
              </div>
            </div>
            <span className="text-[11px] sm:text-xs font-sans text-[#ebeced] leading-tight">
              {score.trust_score > 70 ? 'Verified Chain' : score.trust_score > 30 ? 'Partially Unverified' : 'Untrusted Origin'}
            </span>
          </div>
        </div>

        {/* Executive Summary & Logical Investigation Point-wise Findings */}
        <div className="lg:col-span-8 card-console flex flex-col justify-between p-4 sm:p-6">
          <div>
            <div className="flex items-center gap-2 mb-3">
              <ShieldAlert className="w-4 h-4 text-[#fafafa]" />
              <h3 className="font-mono text-xs uppercase tracking-wider text-[#fafafa] font-medium">
                DFIR Investigation Summary &amp; Findings
              </h3>
            </div>
            <div className="text-xs sm:text-sm text-[#ebeced] leading-relaxed mb-4 font-sans bg-[#181818] p-4 rounded border border-[#5c5c61]">
              {report.executive_summary}
            </div>

            <h4 className="text-xs font-mono uppercase text-[#a1a1aa] mb-2 font-medium">
              Point-Wise Forensic Highlights:
            </h4>
            <div className="space-y-2">
              {pointFindings.map((finding, idx) => (
                <div key={idx} className="flex items-start gap-2.5 text-xs text-[#fafafa]">
                  <div className="w-1.5 h-1.5 rounded-full bg-[#a1a1aa] mt-1.5 shrink-0" />
                  <span className="leading-relaxed font-sans">{finding}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Verdict Reasoning Footnote */}
          <div className="mt-5 pt-3 border-t border-[#5c5c61] text-xs text-[#a1a1aa] font-sans">
            <span className="text-[#fafafa] font-medium">Verdict Rationale: </span>
            {report.verdict_reasoning || 'Incident investigated with RFC 5322 cyber forensic parser.'}
          </div>
        </div>
      </div>

      {/* SECTION 2: 7-Day Threat Trend Heatmap (D3.js Temporal Analysis) */}
      <ThreatTrendHeatmap
        threatScore={score.threat_score}
        threatLevel={score.threat_level}
        category={score.category}
        baseTimestamp={timestamp}
      />

      {/* SECTION 3: Hop-to-Hop MTA Routing Map / Traceroute */}
      <div className="card-console flex flex-col p-4 sm:p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4 sm:mb-5">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-[#fafafa]" />
            <h3 className="font-mono text-xs uppercase tracking-wider text-[#fafafa] font-medium">
              Hop-to-Hop MTA Transmission Route
            </h3>
          </div>
          <span className="text-[11px] sm:text-xs font-mono text-[#a1a1aa] bg-[#181818] px-2.5 py-1 rounded border border-[#5c5c61] self-start sm:self-auto">
            {hopTrace.length} Relay Hops Reconstructed Chronologically
          </span>
        </div>

        {/* Pictorial Flow Route Diagram */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5 sm:gap-4 mb-5 sm:mb-6">
          {hopTrace.map((hop: HopTraceNode, index: number) => {
            const isOrigin = hop.isOrigin || index === 0;
            const isFinal = index === hopTrace.length - 1;

            return (
              <React.Fragment key={hop.hopNumber || index}>
                <div
                  className={`hop-card-item card-hover-highlight relative rounded p-3.5 sm:p-4 border cursor-default ${
                    hop.isSuspicious
                      ? 'bg-[#181818] border-[#fafafa]'
                      : 'bg-[#181818] border-[#5c5c61]'
                  }`}
                >
                  {/* Hop badge & connector */}
                  <div className="flex items-center justify-between mb-2 pb-1.5 border-b border-[#5c5c61]/40">
                    <span className="text-[10px] sm:text-[11px] font-mono px-2 py-0.5 rounded font-medium bg-[#232324] text-[#fafafa] border border-[#5c5c61]">
                      HOP #{hop.hopNumber} {isOrigin ? '· TRUE ORIGIN' : isFinal ? '· INBOUND MX' : '· RELAY'}
                    </span>
                    {hop.isSuspicious && (
                      <span className="text-[10px] font-mono text-[#fafafa] flex items-center gap-1">
                        <AlertTriangle className="w-3 h-3" /> FLAGGED
                      </span>
                    )}
                  </div>

                  {/* Host & IP details */}
                  <div className="space-y-1.5 text-xs font-mono">
                    <div className="flex items-center justify-between">
                      <span className="text-[#a1a1aa]">IP Address:</span>
                      <span className="text-[#fafafa] bg-[#232324] px-1.5 py-0.5 rounded border border-[#5c5c61]">
                        {hop.ip}
                      </span>
                    </div>
                    <div className="flex flex-col">
                      <span className="text-[#a1a1aa] text-[11px]">From Host:</span>
                      <span className="text-[#ebeced] truncate" title={hop.fromHost}>
                        {hop.fromHost || 'unknown'}
                      </span>
                    </div>
                    <div className="flex flex-col">
                      <span className="text-[#a1a1aa] text-[11px]">Received By:</span>
                      <span className="text-[#ebeced] truncate" title={hop.byHost}>
                        {hop.byHost}
                      </span>
                    </div>
                    <div className="pt-2 border-t border-[#5c5c61]/40 text-[11px] text-[#a1a1aa] font-sans">
                      {hop.notes}
                    </div>
                  </div>
                </div>

                {/* Mobile downward flow arrow between hops */}
                {index < hopTrace.length - 1 && (
                  <div className="md:hidden flex items-center justify-center -my-1 text-[#5c5c61] text-xs font-mono">
                    <span>↓ Inbound relay path</span>
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>

        {/* Tabular Details of Hops */}
        <div className="overflow-x-auto rounded border border-[#5c5c61]">
          <table className="w-full text-xs text-left text-[#ebeced] border-collapse min-w-[580px]">
            <thead>
              <tr className="border-b border-[#5c5c61] bg-[#181818] font-mono text-[#a1a1aa]">
                <th className="py-2.5 px-3">Hop</th>
                <th className="py-2.5 px-3">From Host</th>
                <th className="py-2.5 px-3">By Receiving Host</th>
                <th className="py-2.5 px-3">Extracted IP</th>
                <th className="py-2.5 px-3">Protocol</th>
                <th className="py-2.5 px-3">Forensic Assessment</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#5c5c61]/40 font-mono bg-[#232324]">
              {hopTrace.map((hop, i) => (
                <tr key={i} className={hop.isSuspicious ? 'bg-[#181818]' : ''}>
                  <td className="py-2.5 px-3 font-medium text-[#fafafa]">#{hop.hopNumber}</td>
                  <td className="py-2.5 px-3 text-[#ebeced] truncate max-w-[180px]">{hop.fromHost}</td>
                  <td className="py-2.5 px-3 text-[#ebeced] truncate max-w-[180px]">{hop.byHost}</td>
                  <td className="py-2.5 px-3 font-medium text-[#fafafa]">{hop.ip}</td>
                  <td className="py-2.5 px-3 text-[#a1a1aa]">{hop.protocol || 'ESMTPS'}</td>
                  <td className="py-2.5 px-3 font-sans text-[#ebeced]">{hop.notes}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* SECTION 3: Domain Mismatch Matrix & Authentication Audit */}
      <div className="scroll-reveal-item grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6">
        {/* Domain Alignment & Spoofing Matrix */}
        <div className="card-console flex flex-col justify-between p-4 sm:p-6">
          <div>
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
              <div className="flex items-center gap-2">
                <Globe className="w-4 h-4 text-[#fafafa]" />
                <h3 className="font-mono text-xs uppercase tracking-wider text-[#fafafa] font-medium">
                  Domain Mismatch &amp; Spoofing Matrix
                </h3>
              </div>
              <span className={`text-[10px] sm:text-[11px] font-mono px-2.5 py-0.5 rounded border self-start sm:self-auto ${
                domainAnalysis.isMismatch
                  ? 'bg-[#181818] text-[#fafafa] border-[#fafafa] font-medium'
                  : 'bg-[#181818] text-[#a1a1aa] border-[#5c5c61]'
              }`}>
                {domainAnalysis.isMismatch ? 'MISMATCH DETECTED' : 'DOMAINS ALIGNED'}
              </span>
            </div>

            <div className="space-y-2.5 font-mono text-xs">
              <div className="bg-[#181818] p-3 rounded border border-[#5c5c61]">
                <div className="text-[#a1a1aa] text-[11px] mb-0.5">Display Header-From:</div>
                <div className="text-[#fafafa] font-medium break-all">{domainAnalysis.headerFrom || sender}</div>
              </div>

              <div className="bg-[#181818] p-3 rounded border border-[#5c5c61]">
                <div className="text-[#a1a1aa] text-[11px] mb-0.5">Envelope Return-Path:</div>
                <div className="text-[#fafafa] font-medium break-all">{domainAnalysis.returnPath || sender}</div>
              </div>

              {domainAnalysis.replyTo && (
                <div className="bg-[#181818] p-3 rounded border border-[#5c5c61]">
                  <div className="text-[#a1a1aa] text-[11px] mb-0.5">Configured Reply-To:</div>
                  <div className="text-[#fafafa] font-medium break-all">{domainAnalysis.replyTo}</div>
                </div>
              )}

              <div className="bg-[#181818] p-3 rounded border border-[#5c5c61]">
                <div className="text-[#a1a1aa] text-[11px] mb-0.5">DKIM Signing Domain (d=):</div>
                <div className="text-[#fafafa] font-medium break-all">{domainAnalysis.dkimDomain || 'None'}</div>
              </div>
            </div>
          </div>

          <div className="mt-4 p-3 rounded bg-[#181818] border border-[#5c5c61] text-xs font-sans text-[#ebeced]">
            <span className="text-[#fafafa] font-medium">Forensic Assessment: </span>
            {domainAnalysis.notes}
          </div>
        </div>

        {/* Protocol Authentication Audit (SPF / DKIM / DMARC / ARC) */}
        <div className="card-console flex flex-col justify-between p-4 sm:p-6">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Lock className="w-4 h-4 text-[#fafafa]" />
                <h3 className="font-mono text-xs uppercase tracking-wider text-[#fafafa] font-medium">
                  Protocol Authentication Audit
                </h3>
              </div>
              <span className="text-[10px] sm:text-[11px] font-mono text-[#a1a1aa]">
                RFC 7208 / 6376 / 7489
              </span>
            </div>

            <div className="space-y-2.5">
              {authResults.map((auth: AuthCheck, idx: number) => (
                <div
                  key={idx}
                  className="bg-[#181818] border border-[#5c5c61] rounded p-3 flex flex-col gap-1.5 item-hover-glow transition-all"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {getStatusIcon(auth.status)}
                      <span className="font-mono font-medium text-xs text-[#fafafa]">
                        {auth.protocol}
                      </span>
                    </div>
                    <div className="flex items-center gap-1.5 sm:gap-2">
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded uppercase bg-[#232324] border border-[#5c5c61] text-[#fafafa]">
                        {auth.status}
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#232324] border border-[#5c5c61] text-[#a1a1aa]">
                        {auth.aligned ? 'Aligned' : 'Misaligned'}
                      </span>
                    </div>
                  </div>
                  <p className="text-xs text-[#ebeced] font-mono break-words">
                    {auth.details}
                  </p>
                </div>
              ))}
            </div>
          </div>

          {/* Minute Technical Details */}
          <div className="mt-4 pt-3 border-t border-[#5c5c61] text-xs font-mono text-[#a1a1aa] flex flex-wrap gap-2.5 sm:gap-3">
            <span className="break-all">
              <strong>Message-ID:</strong> {minuteDetails.messageIdValidity || 'Syntactically verified RFC 5322 header'}
            </span>
            <span>
              <strong>Priority:</strong> {minuteDetails.priorityFlag || 'Normal'}
            </span>
            {minuteDetails.mailerSoftware && (
              <span>
                <strong>MTA:</strong> {minuteDetails.mailerSoftware}
              </span>
            )}
            {minuteDetails.characterEncoding && (
              <span>
                <strong>Encoding:</strong> {minuteDetails.characterEncoding}
              </span>
            )}
          </div>
        </div>
      </div>

      {/* SECTION 4: Social Engineering Cues, URLs & Attachments */}
      <div className="scroll-reveal-item grid grid-cols-1 lg:grid-cols-3 gap-4 sm:gap-6">
        {/* Social Engineering Cues */}
        <div className="card-console flex flex-col p-4 sm:p-6">
          <div className="flex items-center gap-2 mb-3">
            <AlertTriangle className="w-4 h-4 text-[#fafafa]" />
            <h4 className="font-mono text-xs uppercase tracking-wider text-[#fafafa] font-medium">
              Social Engineering Triggers
            </h4>
          </div>

          <div className="space-y-2.5 flex-1">
            {socialEng.map((se, i) => (
              <div
                key={i}
                className={`p-3 rounded border text-xs ${
                  se.detected
                    ? 'bg-[#181818] border-[#fafafa]'
                    : 'bg-[#181818] border-[#5c5c61]/60 opacity-60'
                }`}
              >
                <div className="flex items-center justify-between font-mono font-medium mb-1">
                  <span className={se.detected ? 'text-[#fafafa]' : 'text-[#a1a1aa]'}>
                    {se.tactic}
                  </span>
                  <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-[#232324] border border-[#5c5c61] text-[#a1a1aa]">
                    {se.detected ? `${se.severity} Severity` : 'Not Detected'}
                  </span>
                </div>
                {se.detected && (
                  <p className="text-[11px] text-[#ebeced] italic font-sans">
                    "{se.evidence}"
                  </p>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* URLs Analyzed */}
        <div className="card-console flex flex-col p-4 sm:p-6">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <ExternalLink className="w-4 h-4 text-[#fafafa]" />
              <h4 className="font-mono text-xs uppercase tracking-wider text-[#fafafa] font-medium">
                Extracted Hyperlinks ({urlsAnalyzed.length})
              </h4>
            </div>
          </div>

          <div className="space-y-2.5 flex-1 overflow-y-auto max-h-[260px]">
            {urlsAnalyzed.length === 0 ? (
              <div className="text-xs text-[#a1a1aa] italic py-8 text-center">
                No external URLs detected in email body.
              </div>
            ) : (
              urlsAnalyzed.map((u, i) => (
                <div key={i} className="bg-[#181818] border border-[#5c5c61] rounded p-2.5 text-xs item-hover-glow cursor-default">
                  <div className="flex items-center justify-between mb-1 gap-2">
                    <span className="font-mono font-medium text-[#fafafa] truncate">
                      {u.displayDomain}
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded uppercase font-medium bg-[#232324] border border-[#5c5c61] text-[#fafafa] shrink-0">
                      {u.riskRating}
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-[#a1a1aa] break-all mb-1" title={u.url}>
                    {u.url}
                  </div>
                  <p className="text-[11px] text-[#ebeced] font-sans">
                    {u.notes}
                  </p>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Attachments & Artifacts */}
        <div className="card-console flex flex-col p-4 sm:p-6">
          <div className="flex items-center gap-2 mb-3">
            <Paperclip className="w-4 h-4 text-[#fafafa]" />
            <h4 className="font-mono text-xs uppercase tracking-wider text-[#fafafa] font-medium">
              Attachments &amp; MIME Assets ({attachmentsAnalyzed.length})
            </h4>
          </div>

          <div className="space-y-2.5 flex-1">
            {attachmentsAnalyzed.length === 0 ? (
              <div className="text-xs text-[#a1a1aa] italic py-8 text-center">
                No binary or image attachments found. Plain text payload.
              </div>
            ) : (
              attachmentsAnalyzed.map((att, i) => (
                <div key={i} className="bg-[#181818] border border-[#5c5c61] rounded p-2.5 text-xs font-mono">
                  <div className="flex items-center justify-between mb-1 gap-2">
                    <span className="font-medium text-[#fafafa] truncate">
                      {att.filename}
                    </span>
                    <span className="text-[10px] bg-[#232324] border border-[#5c5c61] text-[#fafafa] px-1.5 py-0.5 rounded shrink-0">
                      PAYLOAD
                    </span>
                  </div>
                  <div className="text-[11px] text-[#a1a1aa] mb-1">
                    Type: {att.contentType}
                  </div>
                  <p className="text-[11px] text-[#ebeced] font-sans">
                    {att.notes}
                  </p>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* SECTION 5: SOC Actionable Remediation Checklist */}
      <div className="scroll-reveal-item card-console flex flex-col p-4 sm:p-6">
        <div className="flex items-center gap-2 mb-4">
          <Shield className="w-4 h-4 text-[#fafafa]" />
          <h3 className="font-mono text-xs uppercase tracking-wider text-[#fafafa] font-medium">
            Prescriptive SOC Incident Response Actions
          </h3>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {remediationSteps.map((step, idx) => (
            <div
              key={idx}
              className="flex items-start gap-3 bg-[#181818] border border-[#5c5c61] rounded p-3 text-xs item-hover-glow cursor-default transition-all"
            >
              <div className="w-5 h-5 rounded-full bg-[#232324] border border-[#5c5c61] text-[#fafafa] flex items-center justify-center font-mono font-medium text-[11px] shrink-0 mt-0.5">
                {idx + 1}
              </div>
              <span className="text-[#ebeced] leading-relaxed font-sans">{step}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
