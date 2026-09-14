import React, { useState } from 'react';
import { GEMINI_SYSTEM_PROMPT, PYDANTIC_CLASS_DEFINITION, PYTHON_GEMINI_CALL_EXAMPLE } from '../prompts/geminiPrompt';
import { Code2, Copy, Check, Terminal } from 'lucide-react';

interface PromptSpecModalProps {
  onClose?: () => void;
}

export const PromptSpecModal: React.FC<PromptSpecModalProps> = () => {
  const [activeTab, setActiveTab] = useState<'prompt' | 'pydantic' | 'code'>('prompt');
  const [copied, setCopied] = useState<string | null>(null);

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="w-full max-w-[1200px] mx-auto px-3.5 sm:px-6 pt-18 sm:pt-20 pb-28 md:pb-24 flex flex-col gap-4 sm:gap-6">
      {/* Header */}
      <div className="card-console flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3.5 sm:gap-4 p-4 sm:p-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Code2 className="w-4 h-4 text-[#fafafa]" />
            <h2 className="font-mono text-sm font-medium text-[#fafafa]">
              Gemini System Prompt &amp; Pydantic Specification
            </h2>
          </div>
          <p className="text-xs text-[#a1a1aa] font-sans">
            Crafted for deterministic .eml forensic investigation with structured <code className="text-[#fafafa] bg-[#181818] px-1 py-0.5 rounded border border-[#5c5c61]">"score"</code> and <code className="text-[#fafafa] bg-[#181818] px-1 py-0.5 rounded border border-[#5c5c61]">"report"</code> output schema.
          </p>
        </div>

        {/* Tab Selector */}
        <div className="flex items-center bg-[#181818] p-1 rounded-full border border-[#5c5c61] text-xs font-mono overflow-x-auto max-w-full no-scrollbar">
          <button
            onClick={() => setActiveTab('prompt')}
            className={`px-3 py-1.5 rounded-full transition-colors cursor-pointer whitespace-nowrap min-h-[32px] ${
              activeTab === 'prompt' ? 'bg-[#fafafa] text-[#000000] font-medium' : 'text-[#a1a1aa] hover:text-[#fafafa]'
            }`}
          >
            System Prompt
          </button>
          <button
            onClick={() => setActiveTab('pydantic')}
            className={`px-3 py-1.5 rounded-full transition-colors cursor-pointer whitespace-nowrap min-h-[32px] ${
              activeTab === 'pydantic' ? 'bg-[#fafafa] text-[#000000] font-medium' : 'text-[#a1a1aa] hover:text-[#fafafa]'
            }`}
          >
            Pydantic Classes
          </button>
          <button
            onClick={() => setActiveTab('code')}
            className={`px-3 py-1.5 rounded-full transition-colors cursor-pointer whitespace-nowrap min-h-[32px] ${
              activeTab === 'code' ? 'bg-[#fafafa] text-[#000000] font-medium' : 'text-[#a1a1aa] hover:text-[#fafafa]'
            }`}
          >
            Python SDK Code
          </button>
        </div>
      </div>

      {/* Content Container */}
      <div className="card-console p-4 sm:p-5 relative">
        <div className="flex justify-between items-center mb-3 pb-3 border-b border-[#5c5c61]">
          <span className="text-xs font-mono text-[#a1a1aa] flex items-center gap-1.5">
            <Terminal className="w-3.5 h-3.5 text-[#fafafa]" />
            {activeTab === 'prompt' && 'gemini_system_prompt.txt (RFC 5322 Forensics Methodology)'}
            {activeTab === 'pydantic' && 'models.py (Pydantic v2 Schema: Score & Report)'}
            {activeTab === 'code' && 'investigate_eml.py (@google/genai Python SDK Example)'}
          </span>

          <button
            onClick={() => {
              if (activeTab === 'prompt') handleCopy(GEMINI_SYSTEM_PROMPT, 'prompt');
              if (activeTab === 'pydantic') handleCopy(PYDANTIC_CLASS_DEFINITION, 'pydantic');
              if (activeTab === 'code') handleCopy(PYTHON_GEMINI_CALL_EXAMPLE, 'code');
            }}
            className="btn-pill-ghost text-xs py-1 px-3 inline-flex items-center gap-1.5 cursor-pointer"
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5 text-[#fafafa]" />
                <span className="text-[#fafafa]">Copied!</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5 text-[#a1a1aa]" />
                <span>Copy Code</span>
              </>
            )}
          </button>
        </div>

        <pre className="p-4 bg-[#181818] border border-[#5c5c61] text-[#ebeced] font-mono text-xs overflow-x-auto rounded max-h-[600px] leading-relaxed select-all">
          {activeTab === 'prompt' && GEMINI_SYSTEM_PROMPT}
          {activeTab === 'pydantic' && PYDANTIC_CLASS_DEFINITION}
          {activeTab === 'code' && PYTHON_GEMINI_CALL_EXAMPLE}
        </pre>
      </div>
    </div>
  );
};
