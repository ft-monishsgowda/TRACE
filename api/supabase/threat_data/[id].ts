const SUPABASE_DEFAULT_URL =
  process.env.SUPABASE_URL ||
  "https://hnfmtcpxfmyxljilbpte.supabase.co/rest/v1/threat_data";
const SERVER_SUPABASE_KEY =
  process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_KEY || "";

export default async function handler(req: any, res: any) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-supabase-key");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const { id } = req.query;
  if (!id) {
    return res.status(400).json({ error: "Record ID is required" });
  }

  const customKey =
    (req.headers["x-supabase-key"] as string) || SERVER_SUPABASE_KEY;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Prefer: "return=representation",
  };

  if (customKey) {
    headers["apikey"] = customKey;
    headers["Authorization"] = `Bearer ${customKey}`;
  }

  try {
    const response = await fetch(`${SUPABASE_DEFAULT_URL}?id=eq.${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers,
    });

    return res.status(200).json({ success: response.ok });
  } catch (err: any) {
    return res.status(500).json({ error: "Failed to delete record", message: err.message });
  }
}
