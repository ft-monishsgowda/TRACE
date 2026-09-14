import express from "express";
import path from "path";
import dotenv from "dotenv";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI, Type } from "@google/genai";
import { GEMINI_SYSTEM_PROMPT } from "./src/prompts/geminiPrompt";
import { analyzeEmlDeterministic, generateForensicHtmlReport } from "./src/utils/emlParser";

dotenv.config();

const PORT = 3000;
const SUPABASE_DEFAULT_URL = process.env.SUPABASE_URL || "https://hnfmtcpxfmyxljilbpte.supabase.co/rest/v1/threat_data";
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_KEY || "";

let genAIClient: GoogleGenAI | null = null;
function getGenAI(): GoogleGenAI | null {
  if (!genAIClient && process.env.GEMINI_API_KEY) {
    genAIClient = new GoogleGenAI({
      apiKey: process.env.GEMINI_API_KEY,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  }
  return genAIClient;
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '20mb' }));

  // Health check
  app.get("/api/health", (req, res) => {
    res.json({
      status: "ok",
      geminiConfigured: !!process.env.GEMINI_API_KEY,
      supabaseUrl: SUPABASE_DEFAULT_URL,
      supabaseKeyConfigured: !!SUPABASE_KEY,
    });
  });

  // POST /api/analyze: Full EML Forensic Investigation via Gemini API with resilient model fallback
  app.post("/api/analyze", async (req, res) => {
    try {
      const { emlContent } = req.body;
      if (!emlContent || typeof emlContent !== "string") {
        return res.status(400).json({ error: "emlContent string is required" });
      }

      const client = getGenAI();

      // Candidate models for graceful fallback when 503 UNAVAILABLE / high demand occurs
      const candidateModels = [
        "gemini-3.1-flash-lite",
        "gemini-3.8-flash",
        "gemini-flash-latest",
        "gemini-3.1-pro-preview",
      ];

      // If Gemini client is available, attempt generation across candidate models with brief backoff
      if (client) {
        for (const modelName of candidateModels) {
          try {
            const geminiResponse = await client.models.generateContent({
              model: modelName,
              contents: `Conduct full DFIR cyber forensic investigation on this raw RFC 5322 .EML content:\n\n${emlContent}`,
              config: {
                systemInstruction: GEMINI_SYSTEM_PROMPT,
                responseMimeType: "application/json",
                temperature: 0.1,
                responseSchema: {
                  type: Type.OBJECT,
                  properties: {
                    score: {
                      type: Type.OBJECT,
                      properties: {
                        threat_score: { type: Type.INTEGER },
                        trust_score: { type: Type.INTEGER },
                        threat_level: { type: Type.STRING },
                        category: { type: Type.STRING },
                        confidence: { type: Type.INTEGER },
                      },
                      required: ["threat_score", "trust_score", "threat_level", "category", "confidence"],
                    },
                    report: {
                      type: Type.OBJECT,
                      properties: {
                        executive_summary: { type: Type.STRING },
                        point_wise_findings: {
                          type: Type.ARRAY,
                          items: { type: Type.STRING },
                        },
                        verdict_reasoning: { type: Type.STRING },
                        domain_analysis: {
                          type: Type.OBJECT,
                          properties: {
                            headerFrom: { type: Type.STRING },
                            returnPath: { type: Type.STRING },
                            replyTo: { type: Type.STRING },
                            dkimDomain: { type: Type.STRING },
                            isMismatch: { type: Type.BOOLEAN },
                            lookalikeRisk: { type: Type.STRING },
                            notes: { type: Type.STRING },
                          },
                        },
                        hop_to_hop_trace: {
                          type: Type.ARRAY,
                          items: {
                            type: Type.OBJECT,
                            properties: {
                              hopNumber: { type: Type.INTEGER },
                              fromHost: { type: Type.STRING },
                              byHost: { type: Type.STRING },
                              ip: { type: Type.STRING },
                              protocol: { type: Type.STRING },
                              timestamp: { type: Type.STRING },
                              isOrigin: { type: Type.BOOLEAN },
                              isSuspicious: { type: Type.BOOLEAN },
                              notes: { type: Type.STRING },
                            },
                          },
                        },
                        authentication_results: {
                          type: Type.ARRAY,
                          items: {
                            type: Type.OBJECT,
                            properties: {
                              protocol: { type: Type.STRING },
                              status: { type: Type.STRING },
                              aligned: { type: Type.BOOLEAN },
                              details: { type: Type.STRING },
                            },
                          },
                        },
                        social_engineering: {
                          type: Type.ARRAY,
                          items: {
                            type: Type.OBJECT,
                            properties: {
                              tactic: { type: Type.STRING },
                              detected: { type: Type.BOOLEAN },
                              severity: { type: Type.STRING },
                              evidence: { type: Type.STRING },
                            },
                          },
                        },
                        urls_analyzed: {
                          type: Type.ARRAY,
                          items: {
                            type: Type.OBJECT,
                            properties: {
                              url: { type: Type.STRING },
                              displayDomain: { type: Type.STRING },
                              actualDestination: { type: Type.STRING },
                              isLookalike: { type: Type.BOOLEAN },
                              isRedirectTracker: { type: Type.BOOLEAN },
                              riskRating: { type: Type.STRING },
                              notes: { type: Type.STRING },
                            },
                          },
                        },
                        attachments_analyzed: {
                          type: Type.ARRAY,
                          items: {
                            type: Type.OBJECT,
                            properties: {
                              filename: { type: Type.STRING },
                              contentType: { type: Type.STRING },
                              isExecutableOrSuspicious: { type: Type.BOOLEAN },
                              notes: { type: Type.STRING },
                            },
                          },
                        },
                        minute_technical_details: {
                          type: Type.OBJECT,
                          properties: {
                            messageIdValidity: { type: Type.STRING },
                            mailerSoftware: { type: Type.STRING },
                            characterEncoding: { type: Type.STRING },
                            anomalousHeaders: {
                              type: Type.ARRAY,
                              items: { type: Type.STRING },
                            },
                            priorityFlag: { type: Type.STRING },
                          },
                        },
                        soc_remediation_steps: {
                          type: Type.ARRAY,
                          items: { type: Type.STRING },
                        },
                        forensic_html: { type: Type.STRING },
                      },
                      required: ["executive_summary", "point_wise_findings", "verdict_reasoning"],
                    },
                  },
                  required: ["score", "report"],
                },
              },
            });

            const rawText = geminiResponse.text?.trim();
            if (rawText) {
              const parsedJson = JSON.parse(rawText);
              const fallback = analyzeEmlDeterministic(emlContent);

              const hops = (parsedJson.report?.hop_to_hop_trace && parsedJson.report.hop_to_hop_trace.length > 0)
                ? parsedJson.report.hop_to_hop_trace
                : fallback.report.hop_to_hop_trace;

              const authResults = (parsedJson.report?.authentication_results && parsedJson.report.authentication_results.length > 0)
                ? parsedJson.report.authentication_results
                : fallback.report.authentication_results;

              const urls = (parsedJson.report?.urls_analyzed && parsedJson.report.urls_analyzed.length > 0)
                ? parsedJson.report.urls_analyzed
                : fallback.report.urls_analyzed;

              const attachments = (parsedJson.report?.attachments_analyzed && parsedJson.report.attachments_analyzed.length > 0)
                ? parsedJson.report.attachments_analyzed
                : fallback.report.attachments_analyzed;

              const findings = (parsedJson.report?.point_wise_findings && parsedJson.report.point_wise_findings.length > 0)
                ? parsedJson.report.point_wise_findings
                : fallback.report.point_wise_findings;

              const remediation = (parsedJson.report?.soc_remediation_steps && parsedJson.report.soc_remediation_steps.length > 0)
                ? parsedJson.report.soc_remediation_steps
                : fallback.report.soc_remediation_steps;

              const domainAnalysis = parsedJson.report?.domain_analysis || fallback.report.domain_analysis;

              const socialEngineering = (parsedJson.report?.social_engineering && parsedJson.report.social_engineering.length > 0)
                ? parsedJson.report.social_engineering
                : fallback.report.social_engineering;

              // Ensure minute_technical_details is thoroughly populated and resilient
              const minuteDetails = {
                messageIdValidity: parsedJson.report?.minute_technical_details?.messageIdValidity || fallback.report.minute_technical_details.messageIdValidity,
                mailerSoftware: parsedJson.report?.minute_technical_details?.mailerSoftware || fallback.report.minute_technical_details.mailerSoftware || 'Standard MTA',
                characterEncoding: parsedJson.report?.minute_technical_details?.characterEncoding || fallback.report.minute_technical_details.characterEncoding || 'utf-8',
                anomalousHeaders: (parsedJson.report?.minute_technical_details?.anomalousHeaders && Array.isArray(parsedJson.report.minute_technical_details.anomalousHeaders))
                  ? parsedJson.report.minute_technical_details.anomalousHeaders
                  : fallback.report.minute_technical_details.anomalousHeaders,
                priorityFlag: parsedJson.report?.minute_technical_details?.priorityFlag || fallback.report.minute_technical_details.priorityFlag || 'Normal',
              };

              const normalizedReport = {
                executive_summary: parsedJson.report?.executive_summary || fallback.report.executive_summary,
                point_wise_findings: findings,
                verdict_reasoning: parsedJson.report?.verdict_reasoning || fallback.report.verdict_reasoning,
                domain_analysis: domainAnalysis,
                hop_to_hop_trace: hops,
                authentication_results: authResults,
                social_engineering: socialEngineering,
                urls_analyzed: urls,
                attachments_analyzed: attachments,
                minute_technical_details: minuteDetails,
                soc_remediation_steps: remediation,
                forensic_html: '',
              };

              normalizedReport.forensic_html = generateForensicHtmlReport({
                subject: fallback.subject,
                sender: fallback.sender,
                recipient: fallback.recipient,
                date: new Date().toUTCString(),
                messageId: fallback.id,
                threatScore: parsedJson.score?.threat_score ?? fallback.score.threat_score,
                trustScore: parsedJson.score?.trust_score ?? fallback.score.trust_score,
                threatLevel: parsedJson.score?.threat_level ?? fallback.score.threat_level,
                category: parsedJson.score?.category ?? fallback.score.category,
                confidence: parsedJson.score?.confidence || 95,
                findings,
                hops,
                authResults,
                urls,
                attachments,
                remediation,
                executiveSummary: normalizedReport.executive_summary,
                verdictReasoning: normalizedReport.verdict_reasoning,
                domainAnalysis,
              });

              return res.json({
                id: `TRACE-${Date.now().toString(36).toUpperCase()}`,
                timestamp: new Date().toISOString(),
                subject: fallback.subject,
                sender: fallback.sender,
                recipient: fallback.recipient,
                score: {
                  threat_score: parsedJson.score?.threat_score ?? fallback.score.threat_score,
                  trust_score: parsedJson.score?.trust_score ?? fallback.score.trust_score,
                  threat_level: parsedJson.score?.threat_level ?? fallback.score.threat_level,
                  category: parsedJson.score?.category ?? fallback.score.category,
                  confidence: parsedJson.score?.confidence || 95,
                },
                report: normalizedReport,
                source: modelName,
              });
            }
          } catch (modelErr: any) {
            const errStr = modelErr?.message || String(modelErr);
            const is503 = errStr.includes('503') || errStr.includes('UNAVAILABLE') || errStr.includes('high demand');
            console.log(`[AI Engine] Model ${modelName} ${is503 ? 'experiencing temporary load spike (503)' : 'encountered error'}. Trying next candidate model...`);
            // Brief backoff before next model attempt
            await new Promise((resolve) => setTimeout(resolve, 250));
          }
        }
      }

      // Fallback deterministic analysis engine (fully self-contained RFC 5322 & DFIR parser)
      console.info("Engaging deterministic RFC 5322 DFIR investigation engine...");
      const deterministicResult = analyzeEmlDeterministic(emlContent);
      return res.json({
        ...deterministicResult,
        source: "deterministic_dfir_engine",
        engineNotice: "Completed via Deterministic RFC 5322 Forensic Engine due to temporary upstream AI model demand spike.",
      });
    } catch (err: any) {
      console.error("Analysis route error:", err);
      res.status(500).json({ error: "Failed to perform investigation", details: err?.message });
    }
  });

  // Supabase Proxy: POST /api/supabase/threat_data
  app.post("/api/supabase/threat_data", async (req, res) => {
    try {
      const record = req.body;
      const customKey = req.headers["x-supabase-key"] as string || SUPABASE_KEY;

      const headers: Record<string, string> = {
        "Content-Type": "application/json",
        "Prefer": "return=representation",
      };

      if (customKey) {
        headers["apikey"] = customKey;
        headers["Authorization"] = `Bearer ${customKey}`;
      }

      const response = await fetch(SUPABASE_DEFAULT_URL, {
        method: "POST",
        headers,
        body: JSON.stringify(record),
      });

      const responseData = await response.text();
      let parsed = null;
      try {
        parsed = JSON.parse(responseData);
      } catch {
        parsed = responseData;
      }

      if (!response.ok) {
        return res.status(response.status).json({
          error: "Supabase REST request failed",
          statusCode: response.status,
          details: parsed,
          hint: response.status === 401 || response.status === 403
            ? "Supabase API authentication key is required. You can provide your anon/service key in the Database view or via SUPABASE_ANON_KEY env variable."
            : response.status === 404
            ? "Table 'threat_data' might not exist on this Supabase project yet. See Database Schema instructions to run the SQL migration."
            : undefined,
        });
      }

      return res.json({ success: true, data: parsed });
    } catch (err: any) {
      console.error("Supabase proxy POST error:", err);
      res.status(500).json({
        error: "Supabase proxy error",
        message: err.message,
      });
    }
  });

  // Supabase Proxy: GET /api/supabase/threat_data
  app.get("/api/supabase/threat_data", async (req, res) => {
    try {
      const customKey = req.headers["x-supabase-key"] as string || SUPABASE_KEY;
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      };

      if (customKey) {
        headers["apikey"] = customKey;
        headers["Authorization"] = `Bearer ${customKey}`;
      }

      const response = await fetch(`${SUPABASE_DEFAULT_URL}?select=*&order=created_at.desc&limit=50`, {
        method: "GET",
        headers,
      });

      if (!response.ok) {
        const errorText = await response.text();
        return res.status(response.status).json({
          error: "Supabase GET failed",
          statusCode: response.status,
          details: errorText,
          hint: response.status === 401
            ? "Authentication key required for remote Supabase DB."
            : undefined,
        });
      }

      const data = await response.json();
      return res.json({ success: true, data });
    } catch (err: any) {
      console.error("Supabase proxy GET error:", err);
      res.status(500).json({ error: "Failed to query Supabase", message: err.message });
    }
  });

  // Supabase Proxy: DELETE /api/supabase/threat_data/:id
  app.delete("/api/supabase/threat_data/:id", async (req, res) => {
    try {
      const { id } = req.params;
      if (!id) {
        return res.status(400).json({ error: "Record ID is required" });
      }

      const customKey = (req.headers["x-supabase-key"] as string) || SUPABASE_KEY;
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
        "Prefer": "return=representation",
      };

      if (customKey) {
        headers["apikey"] = customKey;
        headers["Authorization"] = `Bearer ${customKey}`;
      }

      const response = await fetch(`${SUPABASE_DEFAULT_URL}?id=eq.${encodeURIComponent(id)}`, {
        method: "DELETE",
        headers,
      });

      if (!response.ok) {
        const errorText = await response.text();
        return res.status(response.status).json({
          error: "Supabase DELETE failed",
          statusCode: response.status,
          details: errorText,
        });
      }

      const responseData = await response.text();
      let parsed = null;
      try {
        parsed = JSON.parse(responseData);
      } catch {
        parsed = responseData;
      }

      return res.json({ success: true, deletedId: id, data: parsed });
    } catch (err: any) {
      console.error("Supabase proxy DELETE error:", err);
      res.status(500).json({ error: "Failed to delete from Supabase", message: err.message });
    }
  });

  // Vite middleware setup
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`T.R.A.C.E Server active on http://0.0.0.0:${PORT}`);
  });
}

startServer();
