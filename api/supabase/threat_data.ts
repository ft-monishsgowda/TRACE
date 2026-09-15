const SUPABASE_DEFAULT_URL =
  process.env.SUPABASE_URL ||
  "https://hnfmtcpxfmyxljilbpte.supabase.co/rest/v1/threat_data";
const SERVER_SUPABASE_KEY =
  process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_KEY || "";

export default async function handler(req: any, res: any) {
  // CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-supabase-key");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const customKey =
    (req.headers["x-supabase-key"] as string) || SERVER_SUPABASE_KEY;

  const baseHeaders: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (customKey) {
    baseHeaders["apikey"] = customKey;
    baseHeaders["Authorization"] = `Bearer ${customKey}`;
  }

  // --- GET ---
  if (req.method === "GET") {
    try {
      let response = await fetch(
        `${SUPABASE_DEFAULT_URL}?select=*&order=created_at.desc&limit=50`,
        {
          method: "GET",
          headers: baseHeaders,
        }
      );

      if (!response.ok) {
        const checkErr = await response.clone().text();
        if (checkErr.includes("created_at does not exist") || checkErr.includes("42703")) {
          response = await fetch(`${SUPABASE_DEFAULT_URL}?select=*&limit=50`, {
            method: "GET",
            headers: baseHeaders,
          });
        }
      }

      if (!response.ok) {
        const errorText = await response.text();
        return res.status(response.status).json({
          error: "Supabase GET failed",
          statusCode: response.status,
          details: errorText,
          hint:
            response.status === 401 || response.status === 403
              ? "Authentication key required for remote Supabase DB. Enter your anon key in the Database tab."
              : "Table 'threat_data' missing or schema columns unmigrated.",
        });
      }

      const data = await response.json();
      return res.status(200).json({ success: true, data });
    } catch (err: any) {
      return res.status(500).json({ error: "Failed to query Supabase", message: err.message });
    }
  }

  // --- POST ---
  if (req.method === "POST") {
    try {
      const record = typeof req.body === "string" ? JSON.parse(req.body) : { ...req.body };
      if (!record.id) {
        // Generate pseudo-uuid if crypto is available
        record.id = typeof crypto !== "undefined" && crypto.randomUUID ? crypto.randomUUID() : `TRACE-${Date.now()}`;
      }

      const postHeaders = {
        ...baseHeaders,
        Prefer: "return=representation",
      };

      const response = await fetch(SUPABASE_DEFAULT_URL, {
        method: "POST",
        headers: postHeaders,
        body: JSON.stringify(record),
      });

      const raw = await response.text();
      let parsed = null;
      try {
        parsed = JSON.parse(raw);
      } catch {
        parsed = raw;
      }

      if (!response.ok) {
        return res.status(response.status).json({
          error: "Supabase POST failed",
          statusCode: response.status,
          details: parsed,
        });
      }

      return res.status(200).json({ success: true, data: parsed });
    } catch (err: any) {
      return res.status(500).json({ error: "Supabase write error", message: err.message });
    }
  }

  // --- DELETE (if query ?id=... is present) ---
  if (req.method === "DELETE") {
    const id = req.query?.id;
    if (!id) {
      return res.status(400).json({ error: "Record ID required" });
    }

    try {
      const response = await fetch(`${SUPABASE_DEFAULT_URL}?id=eq.${encodeURIComponent(id)}`, {
        method: "DELETE",
        headers: {
          ...baseHeaders,
          Prefer: "return=representation",
        },
      });

      return res.status(200).json({ success: response.ok });
    } catch (err: any) {
      return res.status(500).json({ error: "Delete failed", message: err.message });
    }
  }

  return res.status(405).json({ error: "Method not allowed" });
}
