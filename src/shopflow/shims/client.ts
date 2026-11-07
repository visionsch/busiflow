// Browser API client compatible with the original @appdeploy/client (axios-like).
type Config = { headers?: Record<string, string>; params?: Record<string, unknown> };

export class ApiError extends Error {
  response: { status: number; data: any };
  constructor(status: number, data: any) {
    super((data && typeof data === "object" && data.error) || `Request failed with status ${status}`);
    this.response = { status, data };
  }
}

async function request(method: string, url: string, body?: unknown, config: Config = {}) {
  let full = url;
  if (config.params) {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(config.params)) if (v !== undefined && v !== null) qs.set(k, String(v));
    const s = qs.toString();
    if (s) full += (full.includes("?") ? "&" : "?") + s;
  }
  const headers: Record<string, string> = { accept: "application/json", ...(config.headers || {}) };
  let payload: BodyInit | null = null;
  if (body !== undefined && method !== "GET") {
    headers["content-type"] = headers["content-type"] || "application/json";
    payload = typeof body === "string" ? body : JSON.stringify(body);
  }
  const r = await fetch(full, { method, headers, body: payload, credentials: "include" });
  const text = await r.text();
  let data: any = text;
  try { data = text ? JSON.parse(text) : null; } catch { /* keep text */ }
  if (!r.ok) throw new ApiError(r.status, data);
  return { data, status: r.status, headers: r.headers };
}

export const api = {
  get: (url: string, config?: Config) => request("GET", url, undefined, config),
  delete: (url: string, config?: Config) => request("DELETE", url, undefined, config),
  post: (url: string, body?: unknown, config?: Config) => request("POST", url, body, config),
  put: (url: string, body?: unknown, config?: Config) => request("PUT", url, body, config),
  patch: (url: string, body?: unknown, config?: Config) => request("PATCH", url, body, config),
};
export default api;
