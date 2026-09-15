import React, { useState, useEffect, useRef } from 'react';
import { Download, FileText, Copy, Check, Printer, Eye, Code2, ZoomIn, ZoomOut, RotateCcw } from 'lucide-react';
import { exportReportToPdf, downloadHtmlFile } from '../utils/pdfExport';
import { animateViewTransition } from '../utils/animations';

interface ForensicReportViewerProps {
  htmlReport: string;
  caseSubject: string;
  threatScore: number;
}

export const ForensicReportViewer: React.FC<ForensicReportViewerProps> = ({
  htmlReport,
  caseSubject,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [copied, setCopied] = useState(false);
  const [viewMode, setViewMode] = useState<'rendered' | 'source'>('rendered');
  const [isExporting, setIsExporting] = useState(false);
  const [zoomLevel, setZoomLevel] = useState<number>(100);

  // Compute total A4 sheets present in the generated report
  const pageMatches = htmlReport.match(/class=["']pdf-page["']/g) || [];
  const sheetCount = Math.max(pageMatches.length, 3);

  useEffect(() => {
    if (containerRef.current) {
      animateViewTransition(containerRef.current);
    }
  }, []);

  const handleCopyHtml = () => {
    navigator.clipboard.writeText(htmlReport);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadPdf = async () => {
    setIsExporting(true);
    const sanitizedTitle = caseSubject.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 30);
    const filename = `TRACE_Forensic_${sanitizedTitle || 'Report'}.pdf`;
    await exportReportToPdf('renderedForensicDocument', filename);
    setIsExporting(false);
  };

  const handleDownloadHtml = () => {
    const sanitizedTitle = caseSubject.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 30);
    downloadHtmlFile(htmlReport, `TRACE_Report_${sanitizedTitle || 'Case'}.html`);
  };

  const handleZoom = (delta: number) => {
    setZoomLevel((prev) => Math.min(130, Math.max(70, prev + delta)));
  };

  return (
    <div ref={containerRef} className="w-full max-w-[1240px] mx-auto px-3 sm:px-6 pt-18 sm:pt-20 pb-28 md:pb-24 flex flex-col gap-4 sm:gap-5">
      {/* Header Bar */}
      <div className="card-console flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-4 sm:p-6">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded bg-[#181818] border border-[#5c5c61] flex items-center justify-center text-[#fafafa] shrink-0">
            <FileText className="w-4 h-4" />
          </div>
          <div>
            <h2 className="font-mono text-sm font-medium text-[#fafafa]">
              Standalone HTML Forensic Dossier
            </h2>
            <p className="text-xs text-[#a1a1aa] font-sans">
              Formatted for SOC DFIR incident case dossiers, print previews &amp; vector PDF export
            </p>
          </div>
        </div>

        {/* View mode toggle & action buttons */}
        <div className="flex flex-wrap items-center gap-2">
          {/* A4 Sheet Indicator & Quick Jumpers */}
          {viewMode === 'rendered' && (
            <div className="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-[#181818] border border-[#5c5c61] text-xs font-mono text-[#a1a1aa]">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
              <span>A4 ({sheetCount} Sheets)</span>
              <div className="flex items-center gap-1 ml-1 pl-1.5 border-l border-[#5c5c61]">
                {Array.from({ length: sheetCount }).map((_, idx) => {
                  const pNum = idx + 1;
                  return (
                    <button
                      key={pNum}
                      onClick={() => {
                        const target = document.getElementById(`report-page-${pNum}`);
                        if (target) {
                          target.scrollIntoView({ behavior: 'smooth', block: 'start' });
                        }
                      }}
                      className="px-1.5 py-0.5 text-[10px] rounded hover:bg-[#2e2e2e] hover:text-[#fafafa] text-[#ebeced] transition-colors cursor-pointer"
                      title={`Jump to A4 Sheet ${pNum}`}
                    >
                      S{pNum}
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* Zoom controls for comfortable reading */}
          {viewMode === 'rendered' && (
            <div className="flex items-center bg-[#181818] px-2 py-1 rounded-full border border-[#5c5c61] text-xs font-mono text-[#ebeced] gap-1">
              <button
                onClick={() => handleZoom(-10)}
                disabled={zoomLevel <= 70}
                className="hover:text-[#fafafa] p-1 disabled:opacity-30 cursor-pointer min-h-[32px] flex items-center"
                title="Zoom Out"
              >
                <ZoomOut className="w-3.5 h-3.5" />
              </button>
              <span className="px-1 text-[11px] font-medium min-w-[38px] text-center">
                {zoomLevel}%
              </span>
              <button
                onClick={() => handleZoom(10)}
                disabled={zoomLevel >= 130}
                className="hover:text-[#fafafa] p-1 disabled:opacity-30 cursor-pointer min-h-[32px] flex items-center"
                title="Zoom In"
              >
                <ZoomIn className="w-3.5 h-3.5" />
              </button>
              {zoomLevel !== 100 && (
                <button
                  onClick={() => setZoomLevel(100)}
                  className="hover:text-[#fafafa] p-1 text-[#a1a1aa] cursor-pointer min-h-[32px] flex items-center"
                  title="Reset Zoom"
                >
                  <RotateCcw className="w-3 h-3" />
                </button>
              )}
            </div>
          )}

          {/* Toggle between Rendered & Raw HTML */}
          <div className="flex items-center bg-[#181818] p-1 rounded-full border border-[#5c5c61] text-xs font-mono">
            <button
              onClick={() => setViewMode('rendered')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full transition-colors cursor-pointer min-h-[32px] ${
                viewMode === 'rendered' ? 'bg-[#fafafa] text-[#000000] font-medium shadow-sm' : 'text-[#a1a1aa] hover:text-[#fafafa]'
              }`}
            >
              <Eye className="w-3.5 h-3.5" />
              <span>Preview</span>
            </button>
            <button
              onClick={() => setViewMode('source')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full transition-colors cursor-pointer min-h-[32px] ${
                viewMode === 'source' ? 'bg-[#fafafa] text-[#000000] font-medium shadow-sm' : 'text-[#a1a1aa] hover:text-[#fafafa]'
              }`}
            >
              <Code2 className="w-3.5 h-3.5" />
              <span>Source</span>
            </button>
          </div>

          <button
            onClick={handleDownloadPdf}
            disabled={isExporting}
            className="btn-pill-primary text-xs py-2 px-3.5 cursor-pointer min-h-[36px]"
          >
            <Download className="w-3.5 h-3.5" />
            <span>{isExporting ? 'Exporting...' : 'PDF'}</span>
          </button>

          <button
            onClick={() => window.print()}
            className="btn-pill-ghost text-xs py-2 px-3 cursor-pointer min-h-[36px]"
            title="Open browser print dialog / Save as PDF"
          >
            <Printer className="w-3.5 h-3.5 text-[#a1a1aa]" />
            <span>Print</span>
          </button>

          <button
            onClick={handleDownloadHtml}
            className="btn-pill-ghost text-xs py-2 px-3 cursor-pointer min-h-[36px]"
          >
            <FileText className="w-3.5 h-3.5 text-[#a1a1aa]" />
            <span>Save .html</span>
          </button>

          <button
            onClick={handleCopyHtml}
            className="btn-pill-ghost text-xs py-2 px-3 cursor-pointer min-h-[36px]"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-[#fafafa]" /> : <Copy className="w-3.5 h-3.5 text-[#a1a1aa]" />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </div>
      </div>

      {/* Main Container */}
      {viewMode === 'rendered' ? (
        <div className="card-console p-2 sm:p-4 overflow-hidden shadow-2xl">
          {/* Embedded Render Container with element ID for PDF conversion */}
          <div
            className="w-full bg-[#3d4043] py-6 sm:py-10 rounded-lg overflow-x-auto flex justify-center shadow-inner transition-all"
            style={{ minHeight: '600px' }}
          >
            <div
              id="renderedForensicDocument"
              className="w-full max-w-[900px] px-2 sm:px-4 flex flex-col items-center transition-transform duration-200 ease-out origin-top"
              style={{
                transform: zoomLevel !== 100 ? `scale(${zoomLevel / 100})` : undefined,
                transformOrigin: 'top center',
              }}
              dangerouslySetInnerHTML={{ __html: htmlReport }}
            />
          </div>
        </div>
      ) : (
        <div className="card-console p-4">
          <pre className="p-4 bg-[#181818] text-[#ebeced] font-mono text-xs overflow-x-auto rounded border border-[#5c5c61] max-h-[700px] leading-relaxed select-all">
            {htmlReport}
          </pre>
        </div>
      )}
    </div>
  );
};
