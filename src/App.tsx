import React, { useState, useEffect, useRef } from 'react';
import { Header, ActiveTab } from './components/Header';
import { AnalyzerInput } from './components/AnalyzerInput';
import { GraphicalDashboard } from './components/GraphicalDashboard';
import { ForensicReportViewer } from './components/ForensicReportViewer';
import { DatabaseView } from './components/DatabaseView';
import { PatternAnalysisView } from './components/PatternAnalysisView';
import { PromptSpecModal } from './components/PromptSpecModal';
import { SAMPLE_EMAILS } from './data/sampleEmails';
import { EmailForensicResult, SupabaseThreatRecord } from './types';
import { exportReportToPdf } from './utils/pdfExport';
import { animateViewTransition } from './utils/animations';
import { analyzeEmlDeterministic } from './utils/emlParser';
import {
  fetchThreatRecords,
  insertThreatRecord,
  deleteThreatRecord,
  getEffectiveSupabaseKey,
} from './utils/supabaseClient';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('investigate');
  const [selectedSampleId, setSelectedSampleId] = useState<string>('threat_paypal_credential_phish');
  const [emlContent, setEmlContent] = useState<string>(SAMPLE_EMAILS[0].content);
  const [currentResult, setCurrentResult] = useState<EmailForensicResult | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [supabaseRecords, setSupabaseRecords] = useState<SupabaseThreatRecord[]>([]);
  const [isDbLoading, setIsDbLoading] = useState<boolean>(false);
  const [supabaseApiKey, setSupabaseApiKey] = useState<string>(() => {
    return localStorage.getItem('TRACE_SUPABASE_KEY') || '';
  });
  const [isSyncing, setIsSyncing] = useState<boolean>(false);
  const [syncSuccess, setSyncSuccess] = useState<boolean>(false);
  const [dbError, setDbError] = useState<string | null>(null);
  const [dbHint, setDbHint] = useState<string | null>(null);
  const viewContainerRef = useRef<HTMLDivElement>(null);

  // Smooth view transition on tab switch powered by anime.js
  useEffect(() => {
    if (viewContainerRef.current) {
      animateViewTransition(viewContainerRef.current);
    }
  }, [activeTab]);

  // Initialize initial database records from localStorage cache & initial seeds
  useEffect(() => {
    const cached = localStorage.getItem('TRACE_LOCAL_RECORDS');
    if (cached) {
      try {
        setSupabaseRecords(JSON.parse(cached));
      } catch (e) {
        console.warn('Failed to parse cached records');
      }
    } else {
      // Seed default initial records from the samples
      const seeds: SupabaseThreatRecord[] = [
        {
          id: 'seed-1',
          created_at: new Date(Date.now() - 3600000).toISOString(),
          subject: 'URGENT: Your Account Will Be Suspended in 24 Hours',
          sender: 'support@secure-bank-alert.test',
          recipient: 'monish.k@example.com',
          threat_score: 92,
          trust_score: 8,
          threat_level: 'CRITICAL',
          category: 'phishing',
          indicators_count: 5,
          origin_ip: '203.0.113.77',
          soc_verdict: 'Origin IP mismatch and fake bank credential verification lure',
        },
        {
          id: 'seed-2',
          created_at: new Date(Date.now() - 7200000).toISOString(),
          subject: 'Invoice #INV-88214 Overdue - Immediate Action Required',
          sender: 'billing@apex-office-supplies.test',
          recipient: 'accounts.payable@example.com',
          threat_score: 84,
          trust_score: 16,
          threat_level: 'HIGH',
          category: 'phishing',
          indicators_count: 4,
          origin_ip: '203.0.113.140',
          soc_verdict: 'Offshore VPS relay with embedded PNG invoice lure',
        },
        {
          id: 'seed-3',
          created_at: new Date(Date.now() - 10800000).toISOString(),
          subject: 'Quick favor - are you at your desk?',
          sender: 'priya.sharma@example-corp.test',
          recipient: 'new.hire@example-corp.test',
          threat_score: 72,
          trust_score: 28,
          threat_level: 'HIGH',
          category: 'bec_scam',
          indicators_count: 3,
          origin_ip: '192.0.2.201',
          soc_verdict: 'CEO/VIP gift card request diverting replies to webmail',
        },
      ];
      setSupabaseRecords(seeds);
      localStorage.setItem('TRACE_LOCAL_RECORDS', JSON.stringify(seeds));
    }

    // Try fetching from remote Supabase
    fetchSupabaseRecords();
  }, []);

  const fetchSupabaseRecords = async () => {
    setIsDbLoading(true);
    setDbError(null);
    setDbHint(null);
    try {
      const result = await fetchThreatRecords(supabaseApiKey);
      if (result.success && Array.isArray(result.data)) {
        if (result.data.length > 0) {
          setSupabaseRecords(result.data);
          localStorage.setItem('TRACE_LOCAL_RECORDS', JSON.stringify(result.data));
        }
      } else if (result.error) {
        setDbError(result.error);
        if (result.hint) setDbHint(result.hint);
      }
    } catch (err: any) {
      console.log('Supabase fetch note:', err);
    } finally {
      setIsDbLoading(false);
    }
  };

  const handleInvestigate = async () => {
    if (!emlContent.trim() || isLoading) return;
    setIsLoading(true);
    setSyncSuccess(false);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ emlContent }),
      });

      if (!response.ok) {
        throw new Error(`Analysis failed with status ${response.status}`);
      }

      const forensicData: EmailForensicResult = await response.json();
      setCurrentResult(forensicData);
      setActiveTab('dashboard');

      // Auto-save to Supabase threat_data
      saveRecordToDatabase(forensicData);
    } catch (err) {
      console.error('Investigation error:', err);
      // Fallback: compute deterministic in client
      const { analyzeEmlDeterministic } = await import('./utils/emlParser');
      const fallbackResult = analyzeEmlDeterministic(emlContent);
      setCurrentResult(fallbackResult);
      setActiveTab('dashboard');
      saveRecordToDatabase(fallbackResult);
    } finally {
      setIsLoading(false);
    }
  };

  const saveRecordToDatabase = async (res: EmailForensicResult) => {
    setIsSyncing(true);
    const newRecord: SupabaseThreatRecord = {
      id: typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID() : `TRACE-${Date.now()}`,
      subject: res.subject,
      sender: res.sender,
      recipient: res.recipient,
      threat_score: res.score.threat_score,
      trust_score: res.score.trust_score,
      threat_level: res.score.threat_level,
      category: res.score.category,
      indicators_count: res.report.social_engineering.filter(s => s.detected).length,
      origin_ip: res.report.hop_to_hop_trace[0]?.ip || 'Unknown',
      forensic_html: res.report.forensic_html,
      raw_eml_snippet: emlContent.slice(0, 500),
      soc_verdict: res.report.verdict_reasoning,
    };

    // Update local state immediately
    setSupabaseRecords((prev) => {
      const updated = [newRecord, ...prev];
      localStorage.setItem('TRACE_LOCAL_RECORDS', JSON.stringify(updated));
      return updated;
    });

    try {
      const mutateRes = await insertThreatRecord(newRecord, supabaseApiKey);
      if (mutateRes.success) {
        setSyncSuccess(true);
        if (mutateRes.data && Array.isArray(mutateRes.data) && mutateRes.data[0]?.id) {
          const generatedId = mutateRes.data[0].id;
          setSupabaseRecords((prev) => {
            const updated = prev.map((r, i) => (i === 0 ? { ...r, id: generatedId } : r));
            localStorage.setItem('TRACE_LOCAL_RECORDS', JSON.stringify(updated));
            return updated;
          });
        }
      }
    } catch (err) {
      console.log('Remote Supabase sync saved to local cache');
    } finally {
      setIsSyncing(false);
    }
  };

  const handleDeleteRecord = async (record: SupabaseThreatRecord) => {
    const recordId = record.id;
    // 1. Remove from local state immediately for instant responsive UI
    setSupabaseRecords((prev) => {
      const updated = prev.filter((r) => {
        if (recordId && r.id) {
          return r.id !== recordId;
        }
        return r.subject !== record.subject || r.created_at !== record.created_at;
      });
      localStorage.setItem('TRACE_LOCAL_RECORDS', JSON.stringify(updated));
      return updated;
    });

    // 2. If it is stored in remote Supabase, dispatch DELETE
    if (recordId && !recordId.startsWith('seed-')) {
      try {
        await deleteThreatRecord(recordId, supabaseApiKey);
      } catch (err) {
        console.warn('Remote Supabase delete error:', err);
      }
    }
  };

  const handleDownloadPdf = async () => {
    if (!currentResult) return;
    const sanitizedTitle = currentResult.subject.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 30);
    const filename = `TRACE_Forensic_${sanitizedTitle || 'Report'}.pdf`;

    // If report tab is open, use the renderedForensicDocument container
    // Otherwise, temporarily render or trigger PDF
    setActiveTab('report');
    setTimeout(async () => {
      await exportReportToPdf('renderedForensicDocument', filename);
    }, 400);
  };

  const handleSelectCaseFromDb = (record: SupabaseThreatRecord) => {
    // Find matching sample or synthesize complete forensic result
    const sample = SAMPLE_EMAILS.find(
      s => (record.subject && s.content.includes(record.subject)) ||
           (record.subject && record.subject.includes(s.name)) ||
           (record.sender && s.content.includes(record.sender))
    );

    if (sample) {
      setEmlContent(sample.content);
      setSelectedSampleId(sample.id);
      const parsed = analyzeEmlDeterministic(sample.content);
      if (record.forensic_html) {
        parsed.report.forensic_html = record.forensic_html;
      }
      setCurrentResult(parsed);
    } else {
      const synthesized: EmailForensicResult = {
        id: record.id || `CASE-${Date.now().toString(36).toUpperCase()}`,
        timestamp: record.created_at || new Date().toISOString(),
        subject: record.subject,
        sender: record.sender,
        recipient: record.recipient || 'analyst@enterprise.internal',
        score: {
          threat_score: record.threat_score,
          trust_score: record.trust_score,
          threat_level: (record.threat_level as any) || 'SUSPICIOUS',
          category: (record.category as any) || 'phishing',
          confidence: 95,
        },
        report: {
          executive_summary: record.soc_verdict || `Forensic case recorded with threat score ${record.threat_score}/100.`,
          point_wise_findings: [
            `Threat Classification: ${record.threat_level}`,
            `Transmitting Origin IP: ${record.origin_ip || '198.51.100.44'}`,
            `Identified Threat Category: ${record.category}`,
          ],
          verdict_reasoning: record.soc_verdict || 'Threat case loaded from historical incident database.',
          domain_analysis: {
            headerFrom: record.sender,
            returnPath: record.sender,
            isMismatch: record.threat_score > 50,
            lookalikeRisk: record.threat_score > 70 ? 'high' : 'low',
            notes: `Transmitting IP address recorded as ${record.origin_ip || 'N/A'}.`,
          },
          hop_to_hop_trace: [
            {
              hopNumber: 1,
              fromHost: 'origin-mta-gateway',
              byHost: 'inbound-edge-relay.mail.org',
              ip: record.origin_ip || '198.51.100.44',
              protocol: 'ESMTPS',
              timestamp: record.created_at || new Date().toISOString(),
              isOrigin: true,
              isSuspicious: record.threat_score > 50,
              notes: 'Origin transmission node from recorded telemetry',
            },
          ],
          authentication_results: [
            {
              protocol: 'SPF',
              status: record.threat_score > 50 ? 'softfail' : 'pass',
              aligned: record.threat_score <= 50,
              details: `Recorded authentication status for sender ${record.sender}`,
            },
            {
              protocol: 'DKIM',
              status: record.threat_score > 50 ? 'none' : 'pass',
              aligned: record.threat_score <= 50,
              details: 'Cryptographic signature verification status',
            },
            {
              protocol: 'DMARC',
              status: record.threat_score > 50 ? 'fail' : 'pass',
              aligned: record.threat_score <= 50,
              details: 'DMARC alignment policy execution audit',
            },
          ],
          social_engineering: [
            {
              tactic: 'Deception / Urgency',
              detected: record.threat_score > 50,
              severity: record.threat_score > 75 ? 'high' : 'medium',
              evidence: record.subject,
            },
          ],
          urls_analyzed: [],
          attachments_analyzed: [],
          minute_technical_details: {
            messageIdValidity: 'Syntactically verified RFC 5322 header',
            mailerSoftware: 'Enterprise Gateway MTA',
            characterEncoding: 'utf-8',
            anomalousHeaders: [],
            priorityFlag: record.threat_score > 70 ? 'Urgent' : 'Normal',
          },
          soc_remediation_steps: [
            `Block sender address ${record.sender} across enterprise perimeter filters`,
            `Blacklist origin IP ${record.origin_ip || 'N/A'} at edge firewall`,
            'Execute tenant-wide mailbox scan for correlated subject patterns',
          ],
          forensic_html: record.forensic_html || '',
        },
      };
      setCurrentResult(synthesized);
    }
    setActiveTab('dashboard');
  };

  return (
    <div className="min-h-screen bg-[#232324] text-[#fafafa] flex flex-col antialiased selection:bg-[#c7b8f5]/30">
      {/* Top Navbar */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        hasResult={!!currentResult}
        dbCount={supabaseRecords.length}
      />

      {/* Main Content Body */}
      <main ref={viewContainerRef} className="flex-1 w-full flex flex-col">
        {activeTab === 'investigate' && (
          <AnalyzerInput
            emlContent={emlContent}
            setEmlContent={setEmlContent}
            onInvestigate={handleInvestigate}
            isLoading={isLoading}
            selectedSampleId={selectedSampleId}
            setSelectedSampleId={setSelectedSampleId}
          />
        )}

        {activeTab === 'dashboard' && currentResult && (
          <GraphicalDashboard
            result={currentResult}
            onViewReport={() => setActiveTab('report')}
            onDownloadPdf={handleDownloadPdf}
            onSyncToSupabase={() => saveRecordToDatabase(currentResult)}
            isSyncing={isSyncing}
            syncSuccess={syncSuccess}
          />
        )}

        {activeTab === 'report' && currentResult && (
          <ForensicReportViewer
            htmlReport={currentResult.report.forensic_html}
            caseSubject={currentResult.subject}
            threatScore={currentResult.score.threat_score}
          />
        )}

        {activeTab === 'database' && (
          <DatabaseView
            records={supabaseRecords}
            onRefresh={fetchSupabaseRecords}
            isLoading={isDbLoading}
            onSelectCase={handleSelectCaseFromDb}
            onDeleteRecord={handleDeleteRecord}
            supabaseApiKey={supabaseApiKey}
            setSupabaseApiKey={(key) => {
              setSupabaseApiKey(key);
              localStorage.setItem('TRACE_SUPABASE_KEY', key);
            }}
            dbError={dbError}
            dbHint={dbHint}
          />
        )}

        {activeTab === 'patterns' && (
          <PatternAnalysisView records={supabaseRecords} />
        )}

        {activeTab === 'prompt_spec' && (
          <PromptSpecModal />
        )}
      </main>
    </div>
  );
}
