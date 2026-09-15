import { SupabaseThreatRecord } from '../types';

export const DEFAULT_SUPABASE_REST_URL = 
  (import.meta.env.VITE_SUPABASE_URL as string) ||
  'https://hnfmtcpxfmyxljilbpte.supabase.co/rest/v1/threat_data';

export interface SupabaseQueryResult {
  success: boolean;
  data?: SupabaseThreatRecord[];
  error?: string;
  hint?: string;
  source: 'proxy' | 'direct' | 'local';
}

export interface SupabaseMutateResult {
  success: boolean;
  data?: any;
  error?: string;
  hint?: string;
  source: 'proxy' | 'direct' | 'local';
}

/**
 * Returns the effective Supabase key from UI state, localStorage, or Vite environment variables.
 */
export function getEffectiveSupabaseKey(explicitKey?: string): string {
  if (explicitKey && explicitKey.trim()) return explicitKey.trim();
  const stored = typeof window !== 'undefined' ? localStorage.getItem('TRACE_SUPABASE_KEY') : null;
  if (stored && stored.trim()) return stored.trim();
  const viteAnon = (import.meta.env.VITE_SUPABASE_ANON_KEY as string) || (import.meta.env.VITE_SUPABASE_KEY as string);
  if (viteAnon && viteAnon.trim()) return viteAnon.trim();
  return '';
}

/**
 * Helper to safely inspect response content type before attempting JSON parsing
 */
async function parseResponseSafely(res: Response): Promise<{ isJson: boolean; data: any; rawText: string }> {
  const rawText = await res.text();
  try {
    const data = JSON.parse(rawText);
    return { isJson: true, data, rawText };
  } catch {
    return { isJson: false, data: null, rawText };
  }
}

/**
 * Fetch records from Supabase:
 * 1. Try local/server proxy (/api/supabase/threat_data)
 * 2. If proxy 404s, returns non-JSON/HTML, or network fails -> Try direct Supabase REST API
 * 3. Returns structured result with clear diagnostic hints
 */
export async function fetchThreatRecords(customKey?: string): Promise<SupabaseQueryResult> {
  const apiKey = getEffectiveSupabaseKey(customKey);
  let proxyAttemptFailed = false;

  // --- Tier 1: Try Proxy (/api/supabase/threat_data) ---
  try {
    const headers: Record<string, string> = {};
    if (apiKey) headers['x-supabase-key'] = apiKey;

    const res = await fetch('/api/supabase/threat_data', { headers });

    // If server responded with 404 or 502/504, or non-JSON (like Vercel HTML fallback), mark proxy failed
    const contentType = res.headers.get('content-type') || '';
    if (res.status === 404 || !contentType.includes('application/json')) {
      proxyAttemptFailed = true;
    } else {
      const { isJson, data } = await parseResponseSafely(res);
      if (isJson && data) {
        if (data.success && Array.isArray(data.data)) {
          return { success: true, data: data.data, source: 'proxy' };
        }
        if (data.error) {
          // If the proxy reached Supabase and returned an authorized error, return it directly
          if (res.status === 401 || res.status === 403 || data.hint) {
            return { success: false, error: data.error, hint: data.hint, source: 'proxy' };
          }
          proxyAttemptFailed = true;
        }
      } else {
        proxyAttemptFailed = true;
      }
    }
  } catch (proxyErr) {
    proxyAttemptFailed = true;
  }

  // --- Tier 2: Direct Browser-to-Supabase REST Call ---
  // If proxy is not available (standard on Vercel static deployments)
  if (proxyAttemptFailed) {
    if (!apiKey) {
      return {
        success: false,
        error: 'Supabase API Key required for remote sync',
        hint: 'Running in direct cloud mode (Vercel/Static). To sync with remote Supabase, enter your project Anon Key in "Schema & Auth" or set VITE_SUPABASE_ANON_KEY in Vercel.',
        source: 'direct',
      };
    }

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'apikey': apiKey,
        'Authorization': `Bearer ${apiKey}`,
      };

      // Try ordered by created_at desc
      let res = await fetch(`${DEFAULT_SUPABASE_REST_URL}?select=*&order=created_at.desc&limit=50`, {
        method: 'GET',
        headers,
      });

      // If created_at column missing, fallback to plain select=*
      if (!res.ok) {
        const errorText = await res.clone().text();
        if (errorText.includes('created_at does not exist') || errorText.includes('42703')) {
          res = await fetch(`${DEFAULT_SUPABASE_REST_URL}?select=*&limit=50`, {
            method: 'GET',
            headers,
          });
        }
      }

      const { isJson, data, rawText } = await parseResponseSafely(res);

      if (res.ok && isJson && Array.isArray(data)) {
        return { success: true, data, source: 'direct' };
      }

      // Handle specific Supabase error codes
      if (res.status === 401 || res.status === 403) {
        return {
          success: false,
          error: 'Supabase API Key Unauthorized',
          hint: 'The provided Supabase key was rejected by the project. Verify your Anon key from the Supabase Project Dashboard -> Settings -> API.',
          source: 'direct',
        };
      }

      if (rawText.includes('42P01') || rawText.includes('does not exist')) {
        return {
          success: false,
          error: "Table 'threat_data' does not exist",
          hint: "Table 'threat_data' was not found on this Supabase project. Open 'Schema & Auth' in the Database tab and run the SQL migration script.",
          source: 'direct',
        };
      }

      return {
        success: false,
        error: `Supabase returned status ${res.status}`,
        hint: (data && data.message) || rawText.slice(0, 150),
        source: 'direct',
      };
    } catch (directErr: any) {
      return {
        success: false,
        error: 'Failed to connect directly to Supabase cloud',
        hint: directErr.message || 'Network error connecting to Supabase endpoint.',
        source: 'direct',
      };
    }
  }

  return {
    success: false,
    error: 'Database connection failed',
    source: 'proxy',
  };
}

/**
 * Save a new threat case record to Supabase:
 * 1. Try proxy
 * 2. Fall back to direct REST
 */
export async function insertThreatRecord(
  record: SupabaseThreatRecord,
  customKey?: string
): Promise<SupabaseMutateResult> {
  const apiKey = getEffectiveSupabaseKey(customKey);
  let proxyAttemptFailed = false;

  // Tier 1: Try Proxy
  try {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (apiKey) headers['x-supabase-key'] = apiKey;

    const res = await fetch('/api/supabase/threat_data', {
      method: 'POST',
      headers,
      body: JSON.stringify(record),
    });

    const contentType = res.headers.get('content-type') || '';
    if (res.status === 404 || !contentType.includes('application/json')) {
      proxyAttemptFailed = true;
    } else {
      const { isJson, data } = await parseResponseSafely(res);
      if (isJson && data) {
        if (data.success) {
          return { success: true, data: data.data, source: 'proxy' };
        }
        if (data.error && (res.status === 401 || res.status === 403 || data.hint)) {
          return { success: false, error: data.error, hint: data.hint, source: 'proxy' };
        }
        proxyAttemptFailed = true;
      } else {
        proxyAttemptFailed = true;
      }
    }
  } catch {
    proxyAttemptFailed = true;
  }

  // Tier 2: Direct REST
  if (proxyAttemptFailed) {
    if (!apiKey) {
      return {
        success: false,
        error: 'Key required for remote cloud sync',
        hint: 'Record saved to local vault. Enter your Supabase key to sync to cloud.',
        source: 'local',
      };
    }

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'Prefer': 'return=representation',
        'apikey': apiKey,
        'Authorization': `Bearer ${apiKey}`,
      };

      const res = await fetch(DEFAULT_SUPABASE_REST_URL, {
        method: 'POST',
        headers,
        body: JSON.stringify(record),
      });

      const { isJson, data, rawText } = await parseResponseSafely(res);

      if (res.ok) {
        return { success: true, data, source: 'direct' };
      }

      if (rawText.includes('42501') || rawText.includes('row-level security')) {
        return {
          success: false,
          error: 'Row Level Security policy blocked insert',
          hint: 'In Supabase SQL Editor, run: create policy "Allow all" on threat_data for all using (true) with check (true);',
          source: 'direct',
        };
      }

      return {
        success: false,
        error: `Supabase write failed (${res.status})`,
        hint: (data && data.message) || rawText.slice(0, 150),
        source: 'direct',
      };
    } catch (directErr: any) {
      return {
        success: false,
        error: 'Failed to write directly to Supabase cloud',
        hint: directErr.message,
        source: 'direct',
      };
    }
  }

  return { success: false, error: 'Write failed', source: 'proxy' };
}

/**
 * Delete a threat case record from Supabase:
 * 1. Try proxy
 * 2. Fall back to direct REST
 */
export async function deleteThreatRecord(
  recordId: string,
  customKey?: string
): Promise<SupabaseMutateResult> {
  const apiKey = getEffectiveSupabaseKey(customKey);
  let proxyAttemptFailed = false;

  // Tier 1: Try Proxy
  try {
    const headers: Record<string, string> = {};
    if (apiKey) headers['x-supabase-key'] = apiKey;

    const res = await fetch(`/api/supabase/threat_data/${encodeURIComponent(recordId)}`, {
      method: 'DELETE',
      headers,
    });

    const contentType = res.headers.get('content-type') || '';
    if (res.status === 404 || !contentType.includes('application/json')) {
      proxyAttemptFailed = true;
    } else {
      const { isJson, data } = await parseResponseSafely(res);
      if (isJson && data && data.success) {
        return { success: true, data: data.data, source: 'proxy' };
      }
      proxyAttemptFailed = true;
    }
  } catch {
    proxyAttemptFailed = true;
  }

  // Tier 2: Direct REST
  if (proxyAttemptFailed && apiKey) {
    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'Prefer': 'return=representation',
        'apikey': apiKey,
        'Authorization': `Bearer ${apiKey}`,
      };

      const res = await fetch(`${DEFAULT_SUPABASE_REST_URL}?id=eq.${encodeURIComponent(recordId)}`, {
        method: 'DELETE',
        headers,
      });

      if (res.ok) {
        return { success: true, source: 'direct' };
      }
    } catch {
      // Ignore network errors on delete
    }
  }

  return { success: true, source: 'local' };
}

/**
 * Test connectivity directly to Supabase to verify endpoint and credentials
 */
export async function testSupabaseConnection(customKey?: string): Promise<{
  ok: boolean;
  status: number;
  message: string;
  hasTable: boolean;
  details?: string;
}> {
  const apiKey = getEffectiveSupabaseKey(customKey);
  if (!apiKey) {
    return {
      ok: false,
      status: 401,
      message: 'No API Key Provided',
      hasTable: false,
      details: 'Provide your Supabase Anon or Service Role key to test connection.',
    };
  }

  try {
    const res = await fetch(`${DEFAULT_SUPABASE_REST_URL}?select=count&limit=1`, {
      method: 'GET',
      headers: {
        'apikey': apiKey,
        'Authorization': `Bearer ${apiKey}`,
      },
    });

    const { data, rawText } = await parseResponseSafely(res);

    if (res.ok) {
      return {
        ok: true,
        status: res.status,
        message: 'Successfully connected to Supabase table `threat_data`',
        hasTable: true,
      };
    }

    if (res.status === 401 || res.status === 403) {
      return {
        ok: false,
        status: res.status,
        message: 'Invalid API Key (Unauthorized)',
        hasTable: false,
        details: 'The provided key was rejected. Confirm you copied the `anon` or `service_role` key from Supabase Dashboard -> Settings -> API.',
      };
    }

    if (rawText.includes('42P01') || rawText.includes('does not exist')) {
      return {
        ok: false,
        status: res.status,
        message: "Table 'threat_data' missing",
        hasTable: false,
        details: "Database credentials are valid, but table 'threat_data' has not been created yet. Run the SQL Migration script in Supabase SQL editor.",
      };
    }

    return {
      ok: false,
      status: res.status,
      message: `Supabase returned HTTP ${res.status}`,
      hasTable: false,
      details: (data && data.message) || rawText.slice(0, 120),
    };
  } catch (err: any) {
    return {
      ok: false,
      status: 0,
      message: 'Network error contacting Supabase',
      hasTable: false,
      details: err.message,
    };
  }
}
