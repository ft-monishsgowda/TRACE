export default function handler(req: any, res: any) {
  const supabaseUrl = process.env.SUPABASE_URL || "https://hnfmtcpxfmyxljilbpte.supabase.co/rest/v1/threat_data";
  const hasKey = !!(process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_KEY);
  const hasGemini = !!process.env.GEMINI_API_KEY;

  res.status(200).json({
    status: "ok",
    environment: "vercel-serverless",
    supabaseUrl,
    supabaseKeyConfigured: hasKey,
    geminiConfigured: hasGemini,
  });
}
