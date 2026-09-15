import React, { useState, useEffect, useRef } from 'react';
import { SupabaseThreatRecord } from '../types';
import {
  Database,
  Search,
  Key,
  RefreshCw,
  Eye,
  Copy,
  Check,
  Trash2,
  AlertCircle,
  CheckCircle2,
  Wifi,
  HardDrive,
  ExternalLink,
} from 'lucide-react';
import { animateViewTransition, animateStaggerItems } from '../utils/animations';
import { testSupabaseConnection } from '../utils/supabaseClient';

interface DatabaseViewProps {
  records: SupabaseThreatRecord[];
  onRefresh: () => void;
  isLoading: boolean;
  onSelectCase: (record: SupabaseThreatRecord) => void;
  onDeleteRecord: (record: SupabaseThreatRecord) => Promise<void> | void;
  supabaseApiKey: string;
  setSupabaseApiKey: (key: string) => void;
  dbError?: string | null;
  dbHint?: string | null;
}

export const DatabaseView: React.FC<DatabaseViewProps> = ({
  records,
  onRefresh,
  isLoading,
  onSelectCase,
  onDeleteRecord,
  supabaseApiKey,
  setSupabaseApiKey,
  dbError,
  dbHint,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterLevel, setFilterLevel] = useState<string>('all');
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [copiedSql, setCopiedSql] = useState(false);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [deleteNotice, setDeleteNotice] = useState<string | null>(null);
  const [isTesting, setIsTesting] = useState(false);
  const [testResult, setTestResult] = useState<{
    ok: boolean;
    message: string;
    details?: string;
  } | null>(null);

  const handleTestConnection = async () => {
    setIsTesting(true);
    setTestResult(null);
    try {
      const res = await testSupabaseConnection(supabaseApiKey);
      setTestResult(res);
      if (res.ok) {
        onRefresh();
      }
    } finally {
      setIsTesting(false);
    }
  };

  useEffect(() => {
    if (containerRef.current) {
      animateViewTransition(containerRef.current);
    }
  }, []);

  useEffect(() => {
    // Stagger table rows whenever filter or records change with smooth human-perceptible pacing
    const timer = setTimeout(() => {
      animateStaggerItems('.db-record-row', 70);
    }, 80);
    return () => clearTimeout(timer);
  }, [filterLevel, searchTerm, records]);

  const filteredRecords = records.filter((rec) => {
    const matchesSearch =
      (rec.subject || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
      (rec.sender || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
      (rec.origin_ip || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
      (rec.category || '').toLowerCase().includes(searchTerm.toLowerCase());

    const matchesFilter =
      filterLevel === 'all' || (rec.threat_level || '').toUpperCase() === filterLevel;

    return matchesSearch && matchesFilter;
  });

  const handleExecuteDelete = async (record: SupabaseThreatRecord, identifier: string) => {
    try {
      setDeletingId(identifier);
      await onDeleteRecord(record);
      setDeleteNotice(`Record "${(record.subject || 'Threat case').slice(0, 35)}" deleted from database.`);
      setConfirmDeleteId(null);
      setTimeout(() => {
        setDeleteNotice(null);
      }, 3500);
    } catch (err) {
      console.error('Delete error:', err);
    } finally {
      setDeletingId(null);
    }
  };

  const SQL_SCHEMA = `-- ==============================================================================
-- T.R.A.C.E Incident Response & Cyber Forensics — Supabase Schema Setup
-- Direct link: https://supabase.com/dashboard/project/hnfmtcpxfmyxljilbpte/sql/new
-- ==============================================================================

-- 1. Create table if not exists
create table if not exists public.threat_data (
  id uuid default gen_random_uuid() primary key,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null,
  subject text,
  sender text,
  recipient text,
  threat_score integer default 0,
  trust_score integer default 100,
  threat_level text default 'UNKNOWN',
  category text default 'unclassified',
  indicators_count integer default 0,
  origin_ip text,
  forensic_html text,
  raw_eml_snippet text,
  soc_verdict text
);

-- 2. Add columns if table already existed with only 'id'
alter table public.threat_data add column if not exists created_at timestamp with time zone default timezone('utc'::text, now());
alter table public.threat_data add column if not exists subject text;
alter table public.threat_data add column if not exists sender text;
alter table public.threat_data add column if not exists recipient text;
alter table public.threat_data add column if not exists threat_score integer default 0;
alter table public.threat_data add column if not exists trust_score integer default 100;
alter table public.threat_data add column if not exists threat_level text default 'UNKNOWN';
alter table public.threat_data add column if not exists category text default 'unclassified';
alter table public.threat_data add column if not exists indicators_count integer default 0;
alter table public.threat_data add column if not exists origin_ip text;
alter table public.threat_data add column if not exists forensic_html text;
alter table public.threat_data add column if not exists raw_eml_snippet text;
alter table public.threat_data add column if not exists soc_verdict text;

-- 3. Enable RLS and grant read/write access to anon & authenticated roles
alter table public.threat_data enable row level security;

drop policy if exists "Allow read, insert and delete on threat_data" on public.threat_data;
drop policy if exists "Allow all on threat_data" on public.threat_data;

create policy "Allow read, insert and delete on threat_data"
  on public.threat_data
  for all
  to anon, authenticated
  using (true)
  with check (true);
`;

  const handleCopySql = () => {
    navigator.clipboard.writeText(SQL_SCHEMA);
    setCopiedSql(true);
    setTimeout(() => setCopiedSql(false), 2000);
  };

  return (
    <div ref={containerRef} className="w-full max-w-[1200px] mx-auto px-3.5 sm:px-6 pt-18 sm:pt-20 pb-28 md:pb-24 flex flex-col gap-4 sm:gap-6">
      {/* Deletion Feedback Banner */}
      {deleteNotice && (
        <div className="card-console bg-[#181818] border border-[#fafafa] p-3 flex items-center justify-between text-xs font-mono animate-fadeIn">
          <div className="flex items-center gap-2 text-[#fafafa]">
            <Check className="w-3.5 h-3.5 text-[#fafafa]" />
            <span>{deleteNotice}</span>
          </div>
          <button
            onClick={() => setDeleteNotice(null)}
            className="text-[#a1a1aa] hover:text-[#fafafa] text-[11px] px-1.5 py-0.5 rounded cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Database Diagnostic & Schema Warning Banner */}
      {dbError && (
        <div className="card-console bg-[#232324] border border-[#f59e0b]/50 p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs font-mono animate-fadeIn">
          <div className="flex items-start gap-2.5">
            <AlertCircle className="w-4 h-4 text-[#f59e0b] shrink-0 mt-0.5" />
            <div>
              <p className="text-[#fafafa] font-medium">
                {dbError.toLowerCase().includes('key') ? 'Supabase Authentication Notice' : `Supabase Notice: ${dbError}`}
              </p>
              {dbHint && <p className="text-[#a1a1aa] text-[11px] mt-0.5 font-sans leading-relaxed">{dbHint}</p>}
            </div>
          </div>
          <button
            onClick={() => setShowConfigModal(true)}
            className="btn-pill-primary text-xs py-1.5 px-3 whitespace-nowrap cursor-pointer shrink-0"
          >
            {dbError.toLowerCase().includes('key') ? 'Connect Supabase Key' : 'View SQL Migration'}
          </button>
        </div>
      )}

      {/* Top Banner */}
      <div className="card-console flex flex-col md:flex-row items-start md:items-center justify-between gap-3.5 sm:gap-4 p-4 sm:p-6">
        <div>
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <Database className="w-4 h-4 text-[#fafafa]" />
            <h2 className="font-mono text-sm font-medium text-[#fafafa]">
              Supabase Threat Cases Database
            </h2>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#181818] text-[#a1a1aa] border border-[#5c5c61]">
              threat_data
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-2 mt-1.5">
            <span className="text-xs text-[#a1a1aa] font-sans break-all">
              Endpoint: <code className="text-[#fafafa] bg-[#181818] px-1.5 py-0.5 rounded border border-[#5c5c61]">https://hnfmtcpxfmyxljilbpte.supabase.co/rest/v1/threat_data</code>
            </span>
            <span className="text-[#5c5c61] hidden sm:inline">·</span>
            {supabaseApiKey ? (
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                <Wifi className="w-3 h-3 text-emerald-400" />
                <span>Cloud Sync Active</span>
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-mono bg-[#181818] text-[#a1a1aa] border border-[#5c5c61]">
                <HardDrive className="w-3 h-3 text-[#a1a1aa]" />
                <span>Local Vault (Vercel Ready)</span>
              </span>
            )}
          </div>
        </div>

        {/* Database Config & Help Buttons */}
        <div className="grid grid-cols-2 sm:flex sm:items-center gap-2 w-full md:w-auto">
          <button
            onClick={() => setShowConfigModal(true)}
            className="btn-pill-ghost text-xs py-2 px-3.5 cursor-pointer justify-center"
          >
            <Key className="w-3.5 h-3.5 text-[#a1a1aa]" />
            <span>Schema &amp; Auth</span>
          </button>

          <button
            onClick={onRefresh}
            disabled={isLoading}
            className="btn-pill-primary text-xs py-2 px-3.5 cursor-pointer justify-center"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Refresh DB</span>
          </button>
        </div>
      </div>

      {/* Search & Filter Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 card-console p-3">
        <div className="relative w-full sm:w-80">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 transform -translate-y-1/2 text-[#a1a1aa]" />
          <input
            type="text"
            placeholder="Search subject, sender, IP..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 bg-[#181818] border border-[#5c5c61] rounded text-xs font-sans text-[#fafafa] placeholder:text-[#a1a1aa] outline-none focus:border-[#fafafa]"
          />
        </div>

        <div className="flex items-center gap-1.5 text-xs font-mono overflow-x-auto pb-1 sm:pb-0 no-scrollbar">
          <span className="text-[#a1a1aa] mr-1 text-[11px] shrink-0">Severity:</span>
          {['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE'].map((lvl) => (
            <button
              key={lvl}
              onClick={() => setFilterLevel(lvl)}
              className={`px-2.5 py-1 rounded-full text-[11px] uppercase transition-colors cursor-pointer shrink-0 ${
                filterLevel === lvl
                  ? 'bg-[#fafafa] text-[#000000] font-medium'
                  : 'text-[#a1a1aa] hover:text-[#fafafa] bg-[#181818] border border-[#5c5c61]'
              }`}
            >
              {lvl}
            </button>
          ))}
        </div>
      </div>

      {/* Threat Records */}
      <div className="card-console overflow-hidden p-0">
        {filteredRecords.length === 0 ? (
          <div className="p-8 sm:p-12 text-center flex flex-col items-center justify-center gap-3">
            <Database className="w-8 h-8 text-[#5c5c61]" />
            <h3 className="font-mono text-sm text-[#fafafa]">No threat case records found</h3>
            <p className="text-xs text-[#a1a1aa] max-w-md font-sans">
              Analyze an .eml email to automatically store and log case telemetry, or check your Supabase API credentials.
            </p>
          </div>
        ) : (
          <>
            {/* Mobile View: Responsive Card List (shown on md:hidden) */}
            <div className="block md:hidden divide-y divide-[#5c5c61]/40 bg-[#232324]">
              {filteredRecords.map((record, index) => {
                const recordKey = record.id || `${record.subject}-${index}`;
                const isConfirming = confirmDeleteId === recordKey;
                const isDeleting = deletingId === recordKey;

                return (
                  <div key={recordKey} className="p-4 flex flex-col gap-2.5">
                    <div className="flex items-start justify-between gap-2">
                      <h4 className="font-mono text-xs font-medium text-[#fafafa] break-words flex-1">
                        {record.subject || '(No Subject)'}
                      </h4>
                      <span className="px-2 py-0.5 rounded border border-[#5c5c61] bg-[#181818] text-[#fafafa] font-medium text-[11px] shrink-0">
                        {record.threat_score}/100
                      </span>
                    </div>

                    <div className="space-y-1 text-xs font-mono text-[#ebeced]">
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="text-[#a1a1aa]">Sender:</span>
                        <span className="truncate max-w-[200px]">{record.sender}</span>
                      </div>
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="text-[#a1a1aa]">Category:</span>
                        <span className="uppercase text-[#a1a1aa]">{record.category?.replace('_', ' ')}</span>
                      </div>
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="text-[#a1a1aa]">Origin IP:</span>
                        <span>{record.origin_ip || 'N/A'}</span>
                      </div>
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="text-[#a1a1aa]">Logged:</span>
                        <span className="font-sans text-[#a1a1aa]">
                          {record.created_at ? new Date(record.created_at).toLocaleDateString() : 'Recent'}
                        </span>
                      </div>
                    </div>

                    {/* Actions Toolbar */}
                    <div className="pt-2 border-t border-[#5c5c61]/30 flex items-center justify-end gap-2">
                      {isConfirming ? (
                        <div className="flex items-center gap-2">
                          <span className="text-[11px] text-red-400 font-mono">Delete?</span>
                          <button
                            onClick={() => handleExecuteDelete(record, recordKey)}
                            disabled={isDeleting}
                            className="px-2.5 py-1.5 rounded bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40 text-xs font-mono transition-colors cursor-pointer flex items-center gap-1 min-h-[36px]"
                          >
                            {isDeleting ? (
                              <RefreshCw className="w-3 h-3 animate-spin" />
                            ) : (
                              <Trash2 className="w-3 h-3" />
                            )}
                            <span>Confirm</span>
                          </button>
                          <button
                            onClick={() => setConfirmDeleteId(null)}
                            disabled={isDeleting}
                            className="px-2.5 py-1.5 rounded bg-[#181818] text-[#a1a1aa] border border-[#5c5c61] text-xs font-mono transition-colors cursor-pointer min-h-[36px]"
                          >
                            Cancel
                          </button>
                        </div>
                      ) : (
                        <div className="flex items-center gap-2 w-full justify-end">
                          <button
                            onClick={() => onSelectCase(record)}
                            className="btn-pill-ghost text-xs py-1.5 px-3 inline-flex items-center gap-1.5 cursor-pointer min-h-[36px]"
                          >
                            <Eye className="w-3.5 h-3.5 text-[#a1a1aa]" />
                            <span>Inspect Case</span>
                          </button>
                          <button
                            onClick={() => setConfirmDeleteId(recordKey)}
                            className="btn-pill-ghost text-xs py-1.5 px-3 inline-flex items-center gap-1.5 hover:text-red-400 hover:border-red-500/40 cursor-pointer text-[#a1a1aa] min-h-[36px]"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                            <span>Delete</span>
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Desktop View: Full Data Table (shown on md:block) */}
            <div className="hidden md:block overflow-x-auto">
              <table className="w-full text-xs text-left text-[#ebeced] border-collapse">
                <thead>
                  <tr className="border-b border-[#5c5c61] bg-[#181818] font-mono text-[#a1a1aa]">
                    <th className="py-3 px-4">Subject</th>
                    <th className="py-3 px-4">Claimed Sender</th>
                    <th className="py-3 px-4">Threat Score</th>
                    <th className="py-3 px-4">Category</th>
                    <th className="py-3 px-4">Origin IP</th>
                    <th className="py-3 px-4">Logged Time</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#5c5c61]/40 font-mono bg-[#232324]">
                  {filteredRecords.map((record, index) => {
                    const recordKey = record.id || `${record.subject}-${index}`;
                    return (
                      <tr key={recordKey} className="db-record-row hover:bg-[#181818] transition-colors">
                        <td className="py-3 px-4 font-medium text-[#fafafa] max-w-[220px] truncate" title={record.subject}>
                          {record.subject || '(No Subject)'}
                        </td>
                        <td className="py-3 px-4 text-[#ebeced] max-w-[180px] truncate" title={record.sender}>
                          {record.sender}
                        </td>
                        <td className="py-3 px-4">
                          <span className="px-2 py-0.5 rounded border border-[#5c5c61] bg-[#181818] text-[#fafafa] font-medium text-[11px]">
                            {record.threat_score}/100 ({record.threat_level})
                          </span>
                        </td>
                        <td className="py-3 px-4 uppercase text-[11px] text-[#a1a1aa]">
                          {record.category?.replace('_', ' ')}
                        </td>
                        <td className="py-3 px-4 text-[#fafafa]">
                          {record.origin_ip || 'N/A'}
                        </td>
                        <td className="py-3 px-4 text-[#a1a1aa] font-sans text-[11px]">
                          {record.created_at ? new Date(record.created_at).toLocaleDateString() : 'Recent'}
                        </td>
                        <td className="py-3 px-4 text-right">
                          {confirmDeleteId === recordKey ? (
                            <div className="flex items-center gap-1.5 justify-end">
                              <span className="text-[11px] text-red-400 font-mono">Delete?</span>
                              <button
                                onClick={() => handleExecuteDelete(record, recordKey)}
                                disabled={deletingId === recordKey}
                                className="px-2 py-1 rounded bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40 text-[11px] font-mono transition-colors cursor-pointer flex items-center gap-1"
                                title="Confirm deletion from database"
                              >
                                {deletingId === recordKey ? (
                                  <RefreshCw className="w-3 h-3 animate-spin" />
                                ) : (
                                  <Trash2 className="w-3 h-3" />
                                )}
                                <span>Yes</span>
                              </button>
                              <button
                                onClick={() => setConfirmDeleteId(null)}
                                disabled={deletingId === recordKey}
                                className="px-2 py-1 rounded bg-[#181818] hover:bg-[#28282a] text-[#a1a1aa] hover:text-[#fafafa] border border-[#5c5c61] text-[11px] font-mono transition-colors cursor-pointer"
                                title="Cancel"
                              >
                                Cancel
                              </button>
                            </div>
                          ) : (
                            <div className="flex items-center gap-1.5 justify-end">
                              <button
                                onClick={() => onSelectCase(record)}
                                className="btn-pill-ghost text-xs py-1 px-2.5 inline-flex items-center gap-1 cursor-pointer"
                                title="Inspect forensic case report"
                              >
                                <Eye className="w-3 h-3 text-[#a1a1aa]" />
                                <span>Inspect</span>
                              </button>
                              <button
                                onClick={() => setConfirmDeleteId(recordKey)}
                                className="btn-pill-ghost text-xs py-1 px-2.5 inline-flex items-center gap-1 hover:text-red-400 hover:border-red-500/40 cursor-pointer text-[#a1a1aa]"
                                title="Delete record from database"
                              >
                                <Trash2 className="w-3 h-3 text-[#a1a1aa] hover:text-red-400" />
                                <span className="hidden sm:inline">Delete</span>
                              </button>
                            </div>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>

      {/* Modal: Schema Configuration & API Authentication Helper */}
      {showConfigModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50 backdrop-blur-sm">
          <div className="card-console max-w-2xl w-full p-6 max-h-[85vh] overflow-y-auto shadow-2xl flex flex-col gap-4">
            <div className="flex items-center justify-between border-b border-[#5c5c61] pb-3">
              <div className="flex items-center gap-2">
                <Database className="w-4 h-4 text-[#fafafa]" />
                <h3 className="font-mono text-sm font-medium text-[#fafafa]">
                  Supabase DB Schema &amp; Authentication Guide
                </h3>
              </div>
              <button
                onClick={() => setShowConfigModal(false)}
                className="text-[#a1a1aa] hover:text-[#fafafa] text-xs font-mono px-2 py-1 bg-[#181818] border border-[#5c5c61] rounded cursor-pointer"
              >
                Close
              </button>
            </div>

            <div className="space-y-5 text-xs font-sans text-[#ebeced]">
              <div>
                <h4 className="font-mono text-xs font-medium text-[#fafafa] mb-1 uppercase tracking-wider">
                  1. Supabase API Authentication
                </h4>
                <p className="text-[#a1a1aa] mb-2 leading-relaxed">
                  To sync data with <code className="text-[#fafafa]">https://hnfmtcpxfmyxljilbpte.supabase.co</code> from anywhere (including Vercel), enter your project's <strong>anon</strong> public API key:
                </p>
                <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
                  <input
                    type="password"
                    placeholder="Enter Supabase anon public key (eyJhbG...)"
                    value={supabaseApiKey}
                    onChange={(e) => {
                      setSupabaseApiKey(e.target.value);
                      setTestResult(null);
                    }}
                    className="flex-1 bg-[#181818] border border-[#5c5c61] rounded px-3 py-2 text-xs font-mono text-[#fafafa] outline-none focus:border-[#fafafa]"
                  />
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => {
                        localStorage.setItem('TRACE_SUPABASE_KEY', supabaseApiKey.trim());
                        onRefresh();
                      }}
                      className="btn-pill-primary text-xs py-2 px-4 cursor-pointer flex-1 sm:flex-initial justify-center"
                    >
                      Save Key
                    </button>
                    <button
                      onClick={handleTestConnection}
                      disabled={isTesting || !supabaseApiKey.trim()}
                      className="btn-pill-ghost text-xs py-2 px-3.5 cursor-pointer flex-1 sm:flex-initial justify-center disabled:opacity-50"
                    >
                      <RefreshCw className={`w-3 h-3 ${isTesting ? 'animate-spin' : ''}`} />
                      <span>{isTesting ? 'Testing...' : 'Test DB'}</span>
                    </button>
                  </div>
                </div>

                {/* Test Feedback */}
                {testResult && (
                  <div
                    className={`mt-2.5 p-2.5 rounded border text-xs font-mono flex items-start gap-2 ${
                      testResult.ok
                        ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                        : 'bg-amber-950/40 border-amber-500/40 text-amber-300'
                    }`}
                  >
                    {testResult.ok ? (
                      <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400 mt-0.5" />
                    ) : (
                      <AlertCircle className="w-4 h-4 shrink-0 text-amber-400 mt-0.5" />
                    )}
                    <div className="flex-1">
                      <p className="font-medium">{testResult.message}</p>
                      {testResult.details && (
                        <p className="text-[11px] opacity-90 mt-0.5 font-sans">{testResult.details}</p>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {/* Vercel Cloud Deployment Info */}
              <div className="bg-[#181818] border border-[#5c5c61] p-3.5 rounded-lg space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="font-mono text-xs font-medium text-[#fafafa] uppercase tracking-wider flex items-center gap-1.5">
                    <ExternalLink className="w-3.5 h-3.5 text-[#a1a1aa]" />
                    <span>2. Vercel Deployment Setup</span>
                  </h4>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#232324] text-[#a1a1aa] border border-[#5c5c61]">
                    Optional Automation
                  </span>
                </div>
                <p className="text-[#a1a1aa] text-[11px] leading-relaxed">
                  When deployed on Vercel, the app works automatically with local persistence. To automatically connect every user's session to your remote Supabase instance without entering keys:
                </p>
                <div className="bg-[#121212] p-2.5 rounded border border-[#333] font-mono text-[11px] text-[#ebeced] space-y-1">
                  <p className="text-[#a1a1aa]"># In Vercel Project Settings → Environment Variables:</p>
                  <p><span className="text-emerald-400">VITE_SUPABASE_ANON_KEY</span> = <span className="text-[#a1a1aa]">&lt;your-supabase-anon-key&gt;</span></p>
                  <p><span className="text-emerald-400">SUPABASE_ANON_KEY</span> = <span className="text-[#a1a1aa]">&lt;your-supabase-anon-key&gt;</span></p>
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <h4 className="font-mono text-xs font-medium text-[#fafafa] uppercase tracking-wider">
                    3. Table Schema Migration SQL
                  </h4>
                  <div className="flex items-center gap-2">
                    <a
                      href="https://supabase.com/dashboard/project/hnfmtcpxfmyxljilbpte/sql/new"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-[11px] font-mono text-[#fafafa] underline hover:text-[#a1a1aa] flex items-center gap-1"
                    >
                      <span>Open SQL Editor</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                    <button
                      onClick={handleCopySql}
                      className="flex items-center gap-1 text-[11px] font-mono text-[#a1a1aa] hover:text-[#fafafa] cursor-pointer"
                    >
                      {copiedSql ? <Check className="w-3 h-3 text-[#fafafa]" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedSql ? 'Copied SQL' : 'Copy SQL'}</span>
                    </button>
                  </div>
                </div>
                <p className="text-[#a1a1aa] mb-2 text-[11px]">
                  If the table hasn't been created yet in your Supabase project, execute this SQL once in Supabase SQL Editor:
                </p>
                <pre className="bg-[#181818] border border-[#5c5c61] p-3 rounded text-[11px] font-mono text-[#ebeced] overflow-x-auto max-h-44 leading-relaxed">
                  {SQL_SCHEMA}
                </pre>
              </div>
            </div>

            <div className="pt-3 border-t border-[#5c5c61] flex justify-end">
              <button
                onClick={() => setShowConfigModal(false)}
                className="btn-pill-primary text-xs py-2 px-4 cursor-pointer"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
