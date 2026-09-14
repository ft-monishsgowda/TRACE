import React, { useEffect, useRef } from 'react';
import { SupabaseThreatRecord } from '../types';
import { Network, Globe, TrendingUp, Cpu } from 'lucide-react';
import { animateNumber, animateViewTransition, animateStaggerItems } from '../utils/animations';
import { animate, stagger } from 'animejs';

interface PatternAnalysisViewProps {
  records: SupabaseThreatRecord[];
}

export const PatternAnalysisView: React.FC<PatternAnalysisViewProps> = ({ records }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const avgScoreRef = useRef<HTMLSpanElement>(null);
  const clusterCountRef = useRef<HTMLSpanElement>(null);
  const relaysCountRef = useRef<HTMLSpanElement>(null);

  // Aggregate IP frequencies
  const ipMap: Record<string, number> = {};
  const categoryMap: Record<string, number> = {};
  let totalScore = 0;

  records.forEach((r) => {
    if (r.origin_ip) {
      ipMap[r.origin_ip] = (ipMap[r.origin_ip] || 0) + 1;
    }
    const cat = r.category || 'unknown';
    categoryMap[cat] = (categoryMap[cat] || 0) + 1;
    totalScore += r.threat_score || 0;
  });

  const avgScore = records.length > 0 ? Math.round(totalScore / records.length) : 0;
  const highRiskCount = records.filter(r => (r.threat_score || 0) >= 60).length;
  const uniqueIpsCount = Object.keys(ipMap).length;
  const topIps = Object.entries(ipMap).sort((a, b) => b[1] - a[1]).slice(0, 5);
  const categories = Object.entries(categoryMap);

  useEffect(() => {
    if (containerRef.current) {
      animateViewTransition(containerRef.current);
    }

    // Number counters
    animateNumber(avgScoreRef.current, 0, avgScore, 700);
    animateNumber(clusterCountRef.current, 0, highRiskCount, 700);
    animateNumber(relaysCountRef.current, 0, uniqueIpsCount, 700);

    // Stagger IP items
    setTimeout(() => {
      animateStaggerItems('.ip-pattern-row', 45);
    }, 80);

    // Animate vector progress bars width smoothly
    try {
      const bars = document.querySelectorAll('.vector-progress-fill');
      bars.forEach((bar) => {
        const targetWidth = bar.getAttribute('data-width') || '0%';
        animate(bar, {
          width: ['0%', targetWidth],
          duration: 1200,
          ease: 'outCubic',
          delay: stagger(120, { start: 150 }),
        });
      });
    } catch (e) {
      console.debug('Bar anim note:', e);
    }
  }, [records, avgScore, highRiskCount, uniqueIpsCount]);

  return (
    <div ref={containerRef} className="w-full max-w-[1200px] mx-auto px-3.5 sm:px-6 pt-18 sm:pt-20 pb-28 md:pb-24 flex flex-col gap-4 sm:gap-6">
      {/* Header */}
      <div className="card-console flex flex-col gap-1 p-4 sm:p-5">
        <div className="flex items-center gap-2 mb-1">
          <Network className="w-4 h-4 text-[#fafafa]" />
          <h2 className="font-mono text-sm font-medium text-[#fafafa]">
            Threat Actor Pattern Analysis &amp; IOC Correlation
          </h2>
        </div>
        <p className="text-xs text-[#a1a1aa] font-sans">
          Cross-case telemetry across {records.length} analyzed email records in memory &amp; Supabase
        </p>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 sm:gap-4">
        <div className="card-console card-hover-highlight p-4 sm:p-5 flex flex-col cursor-default">
          <div className="text-xs font-mono text-[#a1a1aa] mb-1">Average Threat Score</div>
          <div className="text-2xl sm:text-3xl font-mono font-medium text-[#fafafa]">
            <span ref={avgScoreRef}>{avgScore}</span>{' '}
            <span className="text-xs font-mono text-[#a1a1aa]">/ 100</span>
          </div>
          <div className="text-[11px] text-[#a1a1aa] mt-1 font-sans">Based on active investigation dataset</div>
        </div>

        <div className="card-console card-hover-highlight p-4 sm:p-5 flex flex-col cursor-default">
          <div className="text-xs font-mono text-[#a1a1aa] mb-1">High-Risk Attack Clusters</div>
          <div className="text-2xl sm:text-3xl font-mono font-medium text-[#fafafa]">
            <span ref={clusterCountRef}>{highRiskCount}</span>
          </div>
          <div className="text-[11px] text-[#a1a1aa] mt-1 font-sans">Severe or high phishing &amp; BEC cases</div>
        </div>

        <div className="card-console card-hover-highlight p-4 sm:p-5 flex flex-col cursor-default">
          <div className="text-xs font-mono text-[#a1a1aa] mb-1">Unique Originating Relays</div>
          <div className="text-2xl sm:text-3xl font-mono font-medium text-[#fafafa]">
            <span ref={relaysCountRef}>{uniqueIpsCount}</span>
          </div>
          <div className="text-[11px] text-[#a1a1aa] mt-1 font-sans">Monitored sender MTAs in log</div>
        </div>
      </div>

      {/* Pattern Breakdown Columns */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6">
        {/* Origin IP Correlation */}
        <div className="card-console flex flex-col p-4 sm:p-6">
          <div className="flex items-center gap-2 mb-4">
            <Globe className="w-4 h-4 text-[#fafafa]" />
            <h3 className="font-mono text-xs font-medium uppercase tracking-wider text-[#fafafa]">
              Originating MTA Relay IP Distribution
            </h3>
          </div>

          <div className="space-y-2.5 flex-1">
            {topIps.length === 0 ? (
              <div className="text-xs text-[#a1a1aa] py-6 text-center italic font-sans">No IP records logged yet.</div>
            ) : (
              topIps.map(([ip, count], i) => (
                <div key={i} className="ip-pattern-row bg-[#181818] border border-[#5c5c61] rounded p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-1.5 font-mono text-xs">
                  <div className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#fafafa] shrink-0" />
                    <span className="font-medium text-[#fafafa] break-all">{ip}</span>
                  </div>
                  <div className="flex items-center gap-2 self-start sm:self-auto">
                    <span className="text-[#a1a1aa] text-[11px]">{count} occurrence{count > 1 ? 's' : ''}</span>
                    <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-[#232324] border border-[#5c5c61] text-[#fafafa]">
                      IOC Flagged
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Attack Typology Distribution */}
        <div className="card-console flex flex-col p-4 sm:p-6">
          <div className="flex items-center gap-2 mb-4">
            <TrendingUp className="w-4 h-4 text-[#fafafa]" />
            <h3 className="font-mono text-xs font-medium uppercase tracking-wider text-[#fafafa]">
              Classification &amp; Vector Breakdown
            </h3>
          </div>

          <div className="space-y-3 flex-1">
            {categories.length === 0 ? (
              <div className="text-xs text-[#a1a1aa] py-6 text-center italic font-sans">No categories recorded yet.</div>
            ) : (
              categories.map(([cat, count], idx) => {
                const pct = records.length > 0 ? Math.round((count / records.length) * 100) : 0;
                return (
                  <div key={idx} className="bg-[#181818] border border-[#5c5c61] rounded p-3 font-mono text-xs">
                    <div className="flex justify-between items-center mb-1.5">
                      <span className="font-medium uppercase text-[#fafafa]">
                        {cat.replace('_', ' ')}
                      </span>
                      <span className="text-[#a1a1aa] text-[11px]">{count} cases ({pct}%)</span>
                    </div>
                    <div className="w-full bg-[#232324] h-1.5 rounded-full overflow-hidden">
                      <div
                        className="vector-progress-fill bg-aurora h-full rounded-full"
                        data-width={`${pct}%`}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>

      {/* Campaign Heuristics Intelligence Card */}
      <div className="card-console flex flex-col p-6">
        <div className="flex items-center gap-2 mb-4">
          <Cpu className="w-4 h-4 text-[#fafafa]" />
          <h3 className="font-mono text-xs font-medium uppercase tracking-wider text-[#fafafa]">
            Campaign TTP (Tactics, Techniques &amp; Procedures) Heuristics
          </h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-sans text-[#ebeced]">
          <div className="bg-[#181818] p-4 rounded border border-[#5c5c61]">
            <h4 className="font-mono font-medium text-[#fafafa] mb-1.5">Lookalike Domain Masquerading</h4>
            <p className="text-[#a1a1aa] leading-relaxed">
              Attacker constructs cousin domains appending <code className="text-[#fafafa] bg-[#232324] px-1 py-0.5 rounded border border-[#5c5c61]">-alert</code>, <code className="text-[#fafafa] bg-[#232324] px-1 py-0.5 rounded border border-[#5c5c61]">-verification</code>, or <code className="text-[#fafafa] bg-[#232324] px-1 py-0.5 rounded border border-[#5c5c61]">-payment</code> to deceive corporate recipient visual inspection while failing SPF/DKIM alignment.
            </p>
          </div>

          <div className="bg-[#181818] p-4 rounded border border-[#5c5c61]">
            <h4 className="font-mono font-medium text-[#fafafa] mb-1.5">Reply-To Redirection / BEC</h4>
            <p className="text-[#a1a1aa] leading-relaxed">
              Executive display name spoofing paired with a diverter <code className="text-[#fafafa] bg-[#232324] px-1 py-0.5 rounded border border-[#5c5c61]">Reply-To:</code> directing the victim to an external webmail mailbox to evade company email logs.
            </p>
          </div>

          <div className="bg-[#181818] p-4 rounded border border-[#5c5c61]">
            <h4 className="font-mono font-medium text-[#fafafa] mb-1.5">MIME Image Screenshot Invoices</h4>
            <p className="text-[#a1a1aa] leading-relaxed">
              Sending malicious invoice requests as embedded Base64 PNG screenshots to blind text-based keyword mail filters, accompanied by an external payment hyperlink.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
