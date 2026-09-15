import React, { useState, useRef, useEffect, useMemo } from 'react';
import { SAMPLE_EMAILS } from '../data/sampleEmails';
import { Upload, RotateCcw, ArrowRight, Globe } from 'lucide-react';
import { animateViewTransition } from '../utils/animations';
import { animate } from 'animejs';
import { detectEmailLanguage } from '../utils/languageDetector';

interface AnalyzerInputProps {
  emlContent: string;
  setEmlContent: (val: string) => void;
  onInvestigate: () => void;
  isLoading: boolean;
  selectedSampleId: string;
  setSelectedSampleId: (id: string) => void;
}

export const AnalyzerInput: React.FC<AnalyzerInputProps> = ({
  emlContent,
  setEmlContent,
  onInvestigate,
  isLoading,
  selectedSampleId,
  setSelectedSampleId,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dragActive, setDragActive] = useState(false);

  useEffect(() => {
    if (containerRef.current) {
      animateViewTransition(containerRef.current);
    }
  }, []);

  const handleSelectChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const selectedId = e.target.value;
    setSelectedSampleId(selectedId);
    const sample = SAMPLE_EMAILS.find(s => s.id === selectedId);
    if (sample) {
      setEmlContent(sample.content);
      if (textareaRef.current) {
        animate(textareaRef.current, {
          opacity: [0.6, 1],
          duration: 350,
          ease: 'outQuad',
        });
      }
    }
  };

  const handleFileUpload = (file: File) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content) {
        setEmlContent(content);
        setSelectedSampleId('');
      }
    };
    reader.readAsText(file);
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  const selectedSample = SAMPLE_EMAILS.find(s => s.id === selectedSampleId);
  const hasContent = emlContent.trim().length > 0;

  // Real-time language detection on input content
  const detectedLang = useMemo(() => {
    if (!hasContent) return null;
    return detectEmailLanguage(emlContent);
  }, [emlContent, hasContent]);

  return (
    <div ref={containerRef} className="w-full flex flex-col items-center pt-18 sm:pt-20 pb-28 md:pb-20">
      {/* Main Console Editor Container */}
      <div className="w-full max-w-[1200px] px-3.5 sm:px-6 flex flex-col gap-4">
        {/* Sample Selection Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 sm:gap-3 pb-1 sm:pb-2">
          <div className="flex flex-col sm:flex-row sm:items-center gap-1.5 sm:gap-2.5 w-full sm:w-auto">
            <span className="font-sans text-xs font-medium text-[#a1a1aa] shrink-0">
              Select Threat Preset:
            </span>
            <div className="relative w-full sm:w-auto">
              <select
                id="emailDropdown"
                value={selectedSampleId}
                onChange={handleSelectChange}
                className="bg-[#181818] border border-[#5c5c61] rounded text-[#fafafa] py-2 sm:py-1.5 pl-3 pr-8 text-xs font-sans outline-none cursor-pointer w-full sm:w-[320px] hover:border-[#fafafa] transition-colors appearance-none"
              >
                <option value="" disabled hidden>
                  Choose sample threat...
                </option>
                {SAMPLE_EMAILS.map((sample) => (
                  <option key={sample.id} value={sample.id} className="bg-[#232324] text-[#fafafa] text-xs">
                    {sample.name} ({sample.category})
                  </option>
                ))}
              </select>
              <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2.5 text-[#fafafa]">
                <svg className="w-3.5 h-3.5 fill-current" viewBox="0 0 20 20">
                  <path d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" />
                </svg>
              </div>
            </div>
          </div>
        </div>

        {/* Input Wrapper with drag & drop */}
        <div
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
          className="w-full relative flex flex-col"
        >
          <textarea
            ref={textareaRef}
            id="emlInput"
            value={emlContent}
            onChange={(e) => {
              setEmlContent(e.target.value);
              if (selectedSampleId && e.target.value !== selectedSample?.content) {
                setSelectedSampleId('');
              }
            }}
            placeholder="Paste raw RFC 5322 .EML contents here or drop an email file..."
            required
            className={`w-full h-[270px] sm:h-[360px] bg-[#181818] border text-[#fafafa] font-mono text-xs sm:text-[13px] rounded resize-none outline-none transition-all duration-200 p-4 sm:p-6 leading-relaxed hover:border-[#a1a1aa] focus:border-[#fafafa] focus:shadow-[0_0_0_1px_rgba(250,250,250,0.2)] ${
              dragActive
                ? 'border-[#fafafa] bg-[#232324]'
                : hasContent
                ? 'border-[#5c5c61] text-left'
                : 'border-[#5c5c61] text-center pt-[90px] sm:pt-[150px]'
            }`}
          />

          {/* Floating actions in textarea when content is present */}
          {hasContent && (
            <div className="absolute top-2.5 right-2.5 sm:top-3 sm:right-3 flex items-center gap-1.5 sm:gap-2">
              {/* Detected Language Metadata Tag */}
              {detectedLang && (
                <span
                  id="detectedLanguageBadge"
                  className="text-[10px] sm:text-[11px] font-mono text-[#fafafa] bg-[#181818]/95 backdrop-blur-sm px-2 py-0.5 rounded border border-[#5c5c61] flex items-center gap-1 shadow-sm"
                  title={`Email Language: ${detectedLang.name} (${detectedLang.confidence}% confidence)`}
                >
                  <Globe className="w-3 h-3 text-[#a1a1aa]" />
                  <span>{detectedLang.name}</span>
                  <span className="text-[#a1a1aa] font-mono text-[9px]">({detectedLang.code.toUpperCase()})</span>
                </span>
              )}
              <span className="text-[10px] sm:text-[11px] font-mono text-[#a1a1aa] bg-[#232324]/90 backdrop-blur-sm px-2 py-0.5 rounded border border-[#5c5c61]">
                {emlContent.split('\n').length} lines · {Math.round(emlContent.length / 1024)} KB
              </span>
              <button
                type="button"
                onClick={() => {
                  setEmlContent('');
                  setSelectedSampleId('');
                }}
                className="text-xs text-[#a1a1aa] hover:text-[#fafafa] bg-[#232324] hover:bg-[#3f3f46] p-1.5 rounded transition-colors border border-[#5c5c61] cursor-pointer"
                title="Clear input"
              >
                <RotateCcw className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
        </div>

        {/* Bottom Action Toolbar directly below textbox */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-2.5 sm:gap-3 w-full pt-1">
          {/* File upload hidden input and trigger + language detection info */}
          <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
            <input
              type="file"
              ref={fileInputRef}
              onChange={(e) => {
                if (e.target.files && e.target.files[0]) {
                  handleFileUpload(e.target.files[0]);
                }
              }}
              accept=".eml,.txt,.msg"
              className="hidden"
            />
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="btn-pill-ghost text-xs py-2.5 px-4 cursor-pointer w-full sm:w-auto justify-center min-h-[44px]"
              title="Upload .eml from local disk"
            >
              <Upload className="w-3.5 h-3.5 text-[#a1a1aa]" />
              <span>Browse Local .eml</span>
            </button>

            {/* Language preview badge on bottom bar */}
            {detectedLang && hasContent && (
              <div className="hidden sm:flex items-center gap-1.5 text-xs font-mono text-[#ebeced] bg-[#181818] border border-[#5c5c61] px-3 py-2 rounded-full">
                <Globe className="w-3.5 h-3.5 text-[#a1a1aa]" />
                <span className="text-[#a1a1aa]">Detected Language:</span>
                <strong className="text-[#fafafa] font-medium">{detectedLang.name}</strong>
                <span className="text-[10px] text-[#a1a1aa] font-normal">({detectedLang.confidence}% confidence)</span>
              </div>
            )}
          </div>

          {/* Primary CTA */}
          <button
            id="investigateBtn"
            onClick={onInvestigate}
            disabled={isLoading || !hasContent}
            className="btn-pill-primary text-xs sm:text-sm py-2.5 px-6 cursor-pointer w-full sm:w-auto justify-center min-h-[44px]"
          >
            {isLoading ? (
              <>
                <div className="w-4 h-4 border-2 border-[#000000] border-t-transparent rounded-full animate-spin" />
                <span>Investigating Hops &amp; Headers...</span>
              </>
            ) : (
              <>
                <span>Run Forensic Analysis</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
