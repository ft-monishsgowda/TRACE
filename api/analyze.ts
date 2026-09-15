import { GoogleGenAI, Type } from "@google/genai";
import { GEMINI_SYSTEM_PROMPT } from "../src/prompts/geminiPrompt";
import { analyzeEmlDeterministic, generateForensicHtmlReport } from "../src/utils/emlParser";
import { detectEmailLanguage } from "../src/utils/languageDetector";

export default async function handler(req: any, res: any) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
  const emlContent = body?.emlContent;

  if (!emlContent || typeof emlContent !== "string") {
    return res.status(400).json({ error: "emlContent string is required" });
  }

  const geminiKey = process.env.GEMINI_API_KEY || process.env.GEMINI_API_KEY_2 || process.env.GEMINI_API_KEY_3;

  if (!geminiKey) {
    // If no Gemini key is set in Vercel, use high-fidelity deterministic analyzer
    const deterministic = analyzeEmlDeterministic(emlContent);
    return res.status(200).json(deterministic);
  }

  try {
    const ai = new GoogleGenAI({
      apiKey: geminiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });

    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: [
        {
          role: "user",
          parts: [
            {
              text: `Perform deep email forensic analysis on this raw EML file. Output only valid JSON strictly matching the schema:\n\n${emlContent.slice(0, 45000)}`,
            },
          ],
        },
      ],
      config: {
        systemInstruction: GEMINI_SYSTEM_PROMPT,
        responseMimeType: "application/json",
      },
    });

    const text = response.text?.trim() || "";
    const parsed = JSON.parse(text);

    // Merge language detection
    const lang = detectEmailLanguage(emlContent);
    parsed.detectedLanguage = lang;

    // Ensure forensic HTML exists
    if (!parsed.report?.forensic_html) {
      const fallback = analyzeEmlDeterministic(emlContent);
      if (!parsed.report) parsed.report = fallback.report;
      parsed.report.forensic_html = fallback.report.forensic_html;
    }

    return res.status(200).json(parsed);
  } catch (err) {
    // Fall back to deterministic analyzer on error
    const fallback = analyzeEmlDeterministic(emlContent);
    return res.status(200).json(fallback);
  }
}
